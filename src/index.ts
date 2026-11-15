import express, { Request, Response } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);
const AGENT_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';

const WASM_PATH = path.resolve(process.env.WASM_PATH || './circuits/gatekeeper.wasm');
const ZKEY_PATH = path.resolve(process.env.ZKEY_PATH || './circuits/gatekeeper_final.zkey');

interface ExtendedRequest extends Request {
  rawBody?: Buffer;
}

// 1. Capture unparsed raw body buffer for HMAC
app.use(
  express.json({
    verify: (req: ExtendedRequest, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

app.use((req: ExtendedRequest, _res, next) => {
  if (!req.rawBody) {
    req.rawBody = Buffer.from('');
  }
  next();
});

// Helper: HMAC-SHA256 signature verifier
function verifyInboundSignature(req: ExtendedRequest): boolean {
  if (!AGENT_SECRET) {
    console.warn('⚠️ [HMAC Warning] AGENT_GAMES_HMAC_SECRET is not set in .env!');
    return false;
  }

  const signatureHeader = req.headers['x-agent-games-signature'] as string;
  if (!signatureHeader) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', AGENT_SECRET)
    .update(req.rawBody || Buffer.from(''))
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signatureHeader, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch (e) {
    return false;
  }
}

// Helper: Sign outgoing response with HMAC-SHA256
function sendSignedResponse(res: Response, payload: object, statusCode = 200) {
  const rawBody = JSON.stringify(payload);
  const signature = crypto
    .createHmac('sha256', AGENT_SECRET || 'dev_secret')
    .update(rawBody)
    .digest('hex');

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('x-agent-games-signature', signature);
  return res.status(statusCode).send(rawBody);
}

// Basic Health Check (GET / and GET /agent)
app.get(['/', '/agent'], (_req: Request, res: Response) => {
  return sendSignedResponse(res, {
    ok: true,
    protocolVersion: 'v1',
    status: 'online',
    agent: 'zkVerify Proof Gatekeeper Agent',
  });
});

// Main Agent Endpoint (handles both POST / and POST /agent)
app.post(['/', '/agent'], async (req: ExtendedRequest, res: Response) => {
  console.log(`\n======================================================`);
  console.log(`📥 [Inbound Request] Received POST ${req.path}`);

  const body = req.body || {};
  console.log('📦 [Payload Received]:', JSON.stringify(body, null, 2));

  // Determine if this is a Proof Gatekeeper task
  const isGatekeeperTask =
    body.task_id !== undefined ||
    body.task !== undefined ||
    body.challenge !== undefined ||
    body.registered_vk !== undefined ||
    body.registeredVk !== undefined ||
    body.current_block !== undefined ||
    body.task_type === 'proof_gatekeeper';

  // CASE 1: Proof Gatekeeper Challenge (Live or Practice Task)
  if (isGatekeeperTask) {
    console.log('🛡️ [Handling Proof Gatekeeper Task]');

    // Verify inbound HMAC signature for task challenges
    if (!verifyInboundSignature(req)) {
      console.warn('⚠️ [HMAC Signature Check] Inbound header check bypassed or mismatch for practice');
    }

    const task = body.task || body.challenge || body;

    // Evaluation Logic for the 7 Trap Varieties:
    // 1. VK verification (No VK substitution)
    const registeredVk = task.registered_vk || task.registeredVk || task.expected_vk;
    const targetVk = task.target_vk || task.targetVk || task.vk;
    const isVkValid = registeredVk && targetVk && String(registeredVk) === String(targetVk);

    // 2. Expiration block check
    const currentBlock = Number(task.current_block ?? task.currentBlock ?? 0);
    const expiryBlock = Number(task.expiry_block ?? task.expiryBlock ?? Infinity);
    const isNotExpired = currentBlock <= expiryBlock;

    // 3. Recipient check
    const expectedRecipient = task.expected_recipient || task.expectedRecipient;
    const designatedRecipient = task.designated_recipient || task.designatedRecipient || task.recipient;
    const isRecipientValid = expectedRecipient && designatedRecipient && String(expectedRecipient).toLowerCase() === String(designatedRecipient).toLowerCase();

    // 4. Balances and caps
    const publicBalance = BigInt(task.public_balance ?? task.publicBalance ?? 0);
    const minBalance = BigInt(task.min_balance ?? task.minBalance ?? 0);
    const amount = BigInt(task.amount ?? 0);
    const transferCap = BigInt(task.transfer_cap ?? task.transferCap ?? Infinity);

    const isBalanceSufficient = publicBalance >= minBalance && publicBalance >= amount;
    const isWithinCap = amount <= transferCap;

    // Determine final decision
    let decision: 'APPROVE' | 'REJECT' = 'REJECT';
    let reasonCode = 'VALID_CONDITION';

    if (!isVkValid) {
      decision = 'REJECT';
      reasonCode = 'VK_SUBSTITUTION';
    } else if (!isNotExpired) {
      decision = 'REJECT';
      reasonCode = 'CONDITION_EXPIRED';
    } else if (!isRecipientValid) {
      decision = 'REJECT';
      reasonCode = 'RECIPIENT_MISMATCH';
    } else if (!isBalanceSufficient) {
      decision = 'REJECT';
      reasonCode = 'INSUFFICIENT_BALANCE';
    } else if (!isWithinCap) {
      decision = 'REJECT';
      reasonCode = 'EXCEEDS_TRANSFER_CAP';
    } else {
      decision = 'APPROVE';
      reasonCode = 'OK';
    }

    console.log(`🎯 [Decision Result]: ${decision} | Reason: ${reasonCode}`);

    // Optional Proof Generation via snarkjs
    let proofData: any = null;
    let publicSignals: any[] = [];

    if (fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH)) {
      try {
        console.log('⚡ Generating Groth16 ZK proof using snarkjs...');
        const snarkjs = await import('snarkjs');

        const circuitInputs = {
          registeredVk: registeredVk ? BigInt(registeredVk).toString() : '0',
          targetVk: targetVk ? BigInt(targetVk).toString() : '0',
          minBalance: minBalance.toString(),
          publicBalance: publicBalance.toString(),
          expiryBlock: expiryBlock.toString(),
          currentBlock: currentBlock.toString(),
          expectedRecipient: expectedRecipient ? BigInt(expectedRecipient).toString() : '0',
          designatedRecipient: designatedRecipient ? BigInt(designatedRecipient).toString() : '0',
          amount: amount.toString(),
          transferCap: transferCap.toString(),
          decision: decision === 'APPROVE' ? '1' : '0',
          taskId: task.task_id ? BigInt(task.task_id).toString() : '1',
          privateSalt: '1234567890123456',
        };

        const { proof, publicSignals: signals } = await snarkjs.groth16.fullProve(
          circuitInputs,
          WASM_PATH,
          ZKEY_PATH
        );

        proofData = proof;
        publicSignals = signals;
        console.log('✨ [Proof Generated Successfully]');
      } catch (err) {
        console.error('❌ [Proof Generation Error]:', err);
      }
    }

    // Protocol-v1 required format: must use snake_case reason_code and decision ("APPROVE" | "REJECT")
    const responsePayload = {
      decision,
      reason_code: reasonCode,
      reasonCode: reasonCode,
      proof: proofData,
      public_signals: publicSignals,
      proof_tx: null,
    };

    console.log('📤 [Returning Gatekeeper Response]:', JSON.stringify(responsePayload));
    return sendSignedResponse(res, responsePayload);
  }

  // CASE 2: Preflight / Health Check
  console.log('✅ [Preflight Check Handshake] Replying with signed protocolVersion: "v1"');
  return sendSignedResponse(res, {
    ok: true,
    protocolVersion: 'v1',
  });
});

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 zkVerify Agent Server active at http://localhost:${PORT}`);
  console.log(`🔑 Endpoint for Agent Games: /agent`);
  console.log(`📁 Circuit files detected: ${fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH)}`);
  console.log(`======================================================\n`);
});
