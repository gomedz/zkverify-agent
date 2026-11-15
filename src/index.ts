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

// 1. Capture the unparsed raw body buffer to compute HMAC accurately
app.use(
  express.json({
    verify: (req: ExtendedRequest, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Helper: HMAC-SHA256 signature verifier
function verifyInboundSignature(req: ExtendedRequest): boolean {
  if (!AGENT_SECRET) {
    console.warn('⚠️ [HMAC Warning] AGENT_GAMES_HMAC_SECRET is not set in .env!');
    return false;
  }

  const signatureHeader = req.headers['x-agent-games-signature'] as string;
  if (!signatureHeader || !req.rawBody) {
    return false;
  }

  const expectedSignature = crypto
    .createHmac('sha256', AGENT_SECRET)
    .update(req.rawBody)
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

// Basic Health Check (for browser or monitoring ping)
app.get('/', (_req: Request, res: Response) => {
  res.json({
    status: 'online',
    agent: 'zkVerify Proof Gatekeeper Agent',
    protocolVersion: 'v1',
    circuitsAvailable: fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH),
  });
});

// Main Agent Endpoint (Called by agentgames.zkverify.io)
app.post('/agent', async (req: ExtendedRequest, res: Response) => {
  console.log(`\n📥 [Inbound Request] Received POST /agent`);

  // Step A: Inbound HMAC Verification
  if (!verifyInboundSignature(req)) {
    console.error('❌ [HMAC Failed] Signature mismatch or missing header!');
    return res.status(401).json({ error: 'Invalid HMAC signature' });
  }

  const body = req.body || {};
  console.log('📦 [Payload Preview]:', JSON.stringify(body).slice(0, 160) + '...');

  // Step B: Handle Preflight Test
  // The platform tests your endpoint before marking you Active
  if (body.type === 'preflight' || body.action === 'preflight' || body.protocolVersion || Object.keys(body).length === 0) {
    console.log('✅ [Preflight Check Handshake] Replying ok: true');
    return sendSignedResponse(res, {
      ok: true,
      protocolVersion: 'v1',
    });
  }

  // Step C: Handle Proof Gatekeeper Challenge
  if (body.task_type === 'proof_gatekeeper' || body.challenge || body.task) {
    const task = body.task || body.challenge || body;
    console.log(`🛡️ [Evaluating Gatekeeper Task ID]: ${task.task_id || task.id || 'N/A'}`);

    // Evaluation Logic for the 7 Trap Varieties:
    // 1. VK verification (No VK substitution)
    const registeredVk = task.registered_vk || task.registeredVk || task.expected_vk;
    const targetVk = task.target_vk || task.targetVk || task.vk;
    const isVkValid = registeredVk && targetVk && registeredVk === targetVk;

    // 2. Expiration block check
    const currentBlock = Number(task.current_block ?? task.currentBlock ?? 0);
    const expiryBlock = Number(task.expiry_block ?? task.expiryBlock ?? Infinity);
    const isNotExpired = currentBlock <= expiryBlock;

    // 3. Recipient check
    const expectedRecipient = task.expected_recipient || task.expectedRecipient;
    const designatedRecipient = task.designated_recipient || task.designatedRecipient || task.recipient;
    const isRecipientValid = expectedRecipient && designatedRecipient && expectedRecipient === designatedRecipient;

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

    // Step D: Zero-Knowledge Proof Generation via snarkjs
    let proofData: any = null;
    let publicSignals: any[] = [];

    if (fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH)) {
      try {
        console.log('⚡ Generating Groth16 ZK proof using snarkjs...');
        const snarkjs = await import('snarkjs');

        // Map inputs to the Circom circuit signals (camelCase as required by gatekeeper.wasm)
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
    } else {
      console.warn('⚠️ Circuit files (gatekeeper.wasm/zkey) not found in ./circuits. Proceeding without local witness generation.');
    }

    return sendSignedResponse(res, {
      decision,
      reasonCode,
      proof: proofData,
      public_signals: publicSignals,
      proof_tx: null,
    });
  }

  // Fallback for generic tasks or Steal the VFY
  return sendSignedResponse(res, {
    ok: true,
    message: 'Task received',
  });
});

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 zkVerify Agent Server active at http://localhost:${PORT}`);
  console.log(`🔑 Endpoint for Agent Games: /agent`);
  console.log(`📁 Circuit files detected: ${fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH)}`);
  console.log(`======================================================\n`);
});
