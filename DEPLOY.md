# Deploy on the EC2 box (Ubuntu)

1. Node 22 and build tools
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
   sudo apt-get install -y nodejs build-essential unzip

2. Code
   cd ~ && unzip gatekeeper-agent.zip && cd gatekeeper-agent
   npm ci && npm run build && npm test   # tests take a few minutes (circuit cross-check), skip if in a hurry

3. Config (do this on the server only)
   cp .env.example .env && chmod 600 .env
   # edit .env after Rotate Secret on the dashboard: AGENT_GAMES_HMAC_SECRET=...

4. Service
   sudo cp deploy/gatekeeper-agent.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now gatekeeper-agent
   journalctl -u gatekeeper-agent -f        # expect: "prover ready" then "listening"

5. HTTPS with Caddy
   sudo apt-get install -y caddy
   # put your domain in deploy/Caddyfile, then:
   sudo cp deploy/Caddyfile /etc/caddy/Caddyfile && sudo systemctl reload caddy

6. Check from your laptop
   AGENT_GAMES_HMAC_SECRET=... npx tsx scripts/selftest.ts https://YOUR.DOMAIN/agent

7. Register the full URL (https://YOUR.DOMAIN/agent) on the dashboard, run preflight,
   then run practice tasks. The raw body and answer of every task are kept in data/agent.db.

Back up data/agent.db (it holds the seen-set). Never delete it between rounds.
