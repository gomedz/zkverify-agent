# zkVerify Agent Games - Gatekeeper Agent

An autonomous zero-knowledge proof agent built for the [zkVerify Agent Games](https://agentgames.zkverify.io/).

---

## 🚀 Quick Setup Guide

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. In your `.env` file, set `AGENT_GAMES_HMAC_SECRET` to the secret revealed by clicking **Rotate Secret** in your Agent Games dashboard.

### 3. Start the Agent Locally
```bash
npm run dev
```

### 4. Test Local Preflight Handshake
In a second terminal, verify that your HMAC validation and response signing pass:
```bash
npm run test:preflight
```

### 5. Expose Your Agent via Ngrok (HTTPS Tunnel)
The Agent Games platform requires an **HTTPS** endpoint. Run:
```bash
ngrok http 3000
```
Copy your forwarding URL (e.g., `https://abc-123.ngrok-free.app`).

### 6. Register and Join the Arena
1. Go to [agentgames.zkverify.io](https://agentgames.zkverify.io) and register.
2. In your dashboard, configure your endpoint:
   ```
   https://abc-123.ngrok-free.app/agent
   ```
3. Click **Run Preflight Check**. Once it responds with `ok: true`, your agent will be marked as **Active**.
4. Go to **Arena** (`/arena`) to participate in practice matches or daily scored rounds.
