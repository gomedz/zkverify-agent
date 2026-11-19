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

// BN254 scalar field modulus r
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const MAX_BIGINT = 2n ** 256n - 1n;

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

// Helper: Safely convert values to BigInt without throwing RangeError on Infinity or null
function safeBigInt(val: any, fallback: bigint = 0n): bigint {
  if (val === undefined || val === null) return fallback;
  if (val === Infinity || val === 'Infinity') return MAX_BIGINT;
  try {
    return BigInt(val);
  } catch {
    return fallback;
  }
}

// Convert hex string / address / number to valid BN254 field element string
function toFieldString(val: any): string {
  if (val === undefined || val === null) return '0';
  try {
    const bi = BigInt(val);
    return (bi % BN254_R).toString();
  } catch {
    return '0';
  }
}

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
  try {
    console.log(`\n======================================================`);
    console.log(`📥 [Inbound Request] Received POST ${req.path}`);

    const body = req.body || {};
    console.log('📦 [Payload Received]:', JSON.stringify(body, null, 2));

    // Step 1: Preflight handshake
    const isPreflight =
      body.type === 'agent-games.preflight.v1' ||
      body.type === 'preflight' ||
      body.action === 'preflight' ||
      Object.keys(body).length === 0;

    if (isPreflight) {
      console.log('✅ [Preflight Check Handshake] Replying with signed protocolVersion: "v1"');
      return sendSignedResponse(res, {
        ok: true,
        protocolVersion: 'v1',
      });
    }

    // Step 2: Game Challenge / Practice Task
    console.log('🛡️ [Handling Proof Gatekeeper Challenge/Task]');
    const task = body.input || body.task || body.challenge || body.payload || body.data || body;

    // 1. VK verification (No VK substitution)
    const registeredVk = task.registered_vk || task.registeredVk || task.expected_vk;
    const proofVk = task.proof_vk || task.target_vk || task.targetVk || task.vk;
    const isVkValid = registeredVk && proofVk && String(registeredVk).toLowerCase() === String(proofVk).toLowerCase();

    // 2. Expiration block check
    const currentBlock = Number(task.current_block ?? task.currentBlock ?? 0);
    const expiryBlock = Number(task.expiry_block ?? task.expiryBlock ?? Infinity);
    const isNotExpired = currentBlock <= expiryBlock;

    // 3. Recipient check
    const designatedRecipient = task.recipient || task.designated_recipient || task.designatedRecipient;
    const conditionRecipient = task.condition_recipient || task.expected_recipient || task.expectedRecipient;
    const isRecipientValid =
      designatedRecipient &&
      conditionRecipient &&
      String(designatedRecipient).toLowerCase() === String(conditionRecipient).toLowerCase();

    // 4. Balances and caps
    const publicBalance = safeBigInt(task.public_balance ?? task.publicBalance, 0n);
    const minBalance = safeBigInt(task.minimum ?? task.min_balance ?? task.minBalance, 0n);
    const amount = safeBigInt(task.amount, 0n);
    const maxTransfer = safeBigInt(task.max_transfer ?? task.transfer_cap ?? task.transferCap, MAX_BIGINT);

    const isBalanceSufficient = publicBalance >= minBalance && publicBalance >= amount;
    const isWithinCap = amount <= maxTransfer;

    // Determine final decision & matching reason code
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

    // Step 3: Zero-Knowledge Proof Generation via snarkjs
    // Both APPROVE (1) and REJECT (0) decisions are proven cryptographically by the circuit
    let proofData: any = null;
    let publicSignals: any[] = [];

    if (fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH)) {
      try {
        console.log(`⚡ Generating Groth16 ZK proof for decision: ${decision} (${decision === 'APPROVE' ? '1' : '0'})...`);
        const snarkjs = await import('snarkjs');

        // Extract a numeric or field representation for taskId
        let taskIdStr = '1';
        const rawTaskId = task.task_id || body.task_id;
        if (rawTaskId) {
          const hexOnly = String(rawTaskId).replace(/[^0-9a-fA-F]/g, '');
          taskIdStr = toFieldString(hexOnly ? '0x' + hexOnly.slice(-16) : '1');
        }

        // The 13 exact circuit input signals for gatekeeper.wasm
        const circuitInputs = {
          registeredVkHash: toFieldString(registeredVk),
          proofVkHash: toFieldString(proofVk),
          minimum: toFieldString(minBalance),
          publicBalance: toFieldString(publicBalance),
          expiryBlock: toFieldString(expiryBlock),
          currentBlock: toFieldString(currentBlock),
          recipient: toFieldString(designatedRecipient),
          conditionRecipient: toFieldString(conditionRecipient),
          amount: toFieldString(amount),
          maxTransfer: toFieldString(maxTransfer),
          decision: decision === 'APPROVE' ? '1' : '0',
          taskId: taskIdStr,
          salt: '12345678',
        };

        const { proof, publicSignals: signals } = await snarkjs.groth16.fullProve(
          circuitInputs,
          WASM_PATH,
          ZKEY_PATH
        );

        proofData = proof;
        publicSignals = signals;
        console.log('✨ [Proof Generated Successfully! Public Signals Count:', signals.length, ']');
      } catch (err: any) {
        console.error('❌ [Proof Generation Error]:', err.message);
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
  } catch (error) {
    console.error('❌ [Unexpected Server Error Caught]:', error);
    return sendSignedResponse(res, {
      decision: 'REJECT',
      reason_code: 'INTERNAL_ERROR',
      proof: null,
      public_signals: [],
      proof_tx: null,
    });
  }
});

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 zkVerify Agent Server active at http://localhost:${PORT}`);
  console.log(`🔑 Endpoint for Agent Games: /agent`);
  console.log(`📁 Circuit files detected: ${fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH)}`);
  console.log(`======================================================\n`);
});
