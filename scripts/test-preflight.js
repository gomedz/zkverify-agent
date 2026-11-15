import crypto from 'crypto';
import http from 'http';
import dotenv from 'dotenv';

dotenv.config();

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || 'dev_secret_replace_with_real_one_from_dashboard';
const PORT = process.env.PORT || 3000;

console.log('🧪 [Test Suite] Testing Local Preflight Handshake...');
console.log(`🔑 Using HMAC Secret: ${SECRET}`);

const payload = JSON.stringify({
  type: 'preflight',
  protocolVersion: 'v1'
});

const signature = crypto
  .createHmac('sha256', SECRET)
  .update(payload)
  .digest('hex');

const options = {
  hostname: 'localhost',
  port: PORT,
  path: '/agent',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    'x-agent-games-signature': signature
  }
};

const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    console.log(`\nHTTP Status: ${res.statusCode}`);
    console.log(`Response Headers:`, res.headers);
    console.log(`Response Body:`, data);

    const resSignature = res.headers['x-agent-games-signature'];
    if (resSignature) {
      const expectedSig = crypto.createHmac('sha256', SECRET).update(data).digest('hex');
      if (resSignature === expectedSig) {
        console.log('✅ Outbound Response Signature Verified Successfully!');
      } else {
        console.error('❌ Outbound Signature Mismatch!');
      }
    }

    if (res.statusCode === 200) {
      console.log('\n🎉 SUCCESS: Agent is ready to pass the agentgames.zkverify.io Preflight check!');
    } else {
      console.error('\n❌ FAILURE: Response was not 200 OK.');
    }
  });
});

req.on('error', (err) => {
  console.error('\n❌ Connection Error:', err.message);
  console.error('Ensure your agent server is running with: npm run dev');
});

req.write(payload);
req.end();
