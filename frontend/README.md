# Sentinel Prime

Redesign my existing ThreatMail AI frontend into a premium professional SOC / digital forensics dashboard for SIH 2026.

IMPORTANT:

- Improve the existing frontend, do NOT rebuild from scratch.

- Do NOT modify the FastAPI backend.

- Preserve POST /api/analyze, its request format, JSON response, and all existing JavaScript functionality.

- Do not remove any existing feature.

Improve the UI/UX:

- modern dark SOC design

- polished sidebar and navigation

- stronger Overview dashboard

- prominent risk score/severity

- professional .eml upload

- excellent Investigation workspace

- Risk Breakdown

- Threat Relationship Graph (Cytoscape)

- Investigation Timeline

- Threat Intelligence

- Observed Sending Infrastructure map (Leaflet + OpenStreetMap)

- IOC/Indicators

- AI Security Analysis

- Threat Folder

- Reports

- responsive layout

- clean typography, spacing, cards and subtle animations

Keep existing risk scoring, localStorage, DEMO DATA/LIVE API labels, API integration and map behavior.

Keep the exact wording "Observed Sending Infrastructure" and never imply it proves an attacker's physical location.

Design around:

DETECT → INVESTIGATE → CORRELATE → EXPLAIN

Make it look like a real professional cybersecurity investigation platform, not a generic AI dashboard.

UI redesign only. Preserve functionality.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/9108f738-f559-4c3d-9e53-b77219c3e355).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
