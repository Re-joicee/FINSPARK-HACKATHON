# QuantumShield AI

## Run locally

```bash
npm install
npm start
```

Open http://localhost:4000/ to view the SOC console.

## Demo flow

1. Open the Overview tab and review the correlated incident.
2. Open the Attack Graph tab to walk the attack chain.
3. In the Adaptive Response tab, move the slider to change the selected tier.
4. Use the Threat Copilot tab to ask questions about the incident.
5. Trigger the action endpoint to block or resolve the incident.

## API quick reference

- POST /api/score
- GET /api/incident/:id
- POST /api/incident/:id/action
- GET /api/incident/:id/log
- POST /api/adaptive
- POST /api/copilot
- POST /api/twin
