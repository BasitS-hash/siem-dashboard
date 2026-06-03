# SentinelView — Real-Time SIEM Dashboard

> **GMU Hackathon 2026** · Security Information and Event Management Platform

A production-quality Security Information and Event Management (SIEM) dashboard featuring real-time log ingestion, automated threat detection, MITRE ATT&CK aligned alerting, and rich security visualizations.

---

## Screenshots

```
┌─────────────────────────────────────────────────────────────────────┐
│  🛡 SentinelView          Security Overview              09:42:17   │
├──────────┬──────────────────────────────────────────────────────────┤
│ Overview │  [Total Events] [Active Threats] [Critical] [EPM] ...    │
│ Live Feed│                                                          │
│ Alerts   │  ┌─ Events Over Time ───────────────┐ ┌─ Severity ───┐  │
│ Rules    │  │  ▁▂▃▅▄▆▇█▇▅▄▃▂▁ (stacked area) │ │   Donut      │  │
│          │  └──────────────────────────────────┘ └──────────────┘  │
│ CONNECTED│                                                          │
└──────────┴──────────────────────────────────────────────────────────┘
```

## Features

### Core SIEM Capabilities
- **Real-Time Event Stream** — WebSocket-driven live log ingestion at ~75 events/minute
- **Attack Wave Simulation** — Periodic attack bursts from high-risk IPs for realistic demos
- **Threat Detection Engine** — Rules-based detection with configurable thresholds and time windows
- **Alert Management** — Acknowledge / resolve workflow with full audit trail

### Detection Rules (MITRE ATT&CK Aligned)
| Rule | MITRE ID | Severity |
|------|----------|----------|
| SSH/RDP Brute Force | T1110 | High |
| Network Port Scan | T1046 | High |
| SQL Injection | T1190 | Critical |
| Cross-Site Scripting | T1059.007 | High |
| Privilege Escalation | T1548.003 | Critical |
| Reverse Shell / C2 | T1071 | Critical |
| Data Exfiltration | T1041 | Critical |
| Lateral Movement | T1021 | High |
| Sensitive File Access | T1555 | High |
| Cron Persistence | T1053.003 | Critical |
| High-Risk Port Access | T1133 | Medium |
| Recon Tool Detection | T1592 | Medium |

### Dashboard Pages
1. **Overview** — 6 KPI cards, events timeline (area chart), severity donut, top attackers bar, category radar, recent alerts + logs
2. **Live Feed** — Real-time scrolling log table, pause/resume, search, severity/category filters
3. **Alerts** — Alert cards with MITRE tactic/technique badges, status filter tabs, acknowledge/resolve actions
4. **Detection Rules** — All 12 rules with toggle on/off, detection logic, thresholds, MITRE mapping

### Security Event Types
- Authentication (login success/failure, SSH, RDP, LDAP, Kerberos)
- Network (TCP/UDP connections, flags, port scans)
- Web (HTTP methods, SQLi/XSS payloads, path traversal)
- System (process execution, privilege escalation, file access, persistence)
- Firewall (allow/block decisions)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite |
| Styling | Tailwind CSS v3 (dark cyber theme) |
| Charts | Recharts (Area, Pie, Bar, Radar) |
| Icons | Lucide React |
| Real-Time | Socket.io Client |
| Backend | Node.js + Express + Socket.io |
| Language | TypeScript (full-stack) |
| Package Mgmt | npm Workspaces (monorepo) |

---

## Quick Start

### Prerequisites
- Node.js 18+
- npm 8+

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/gmu-hackathon-siem-dashboard.git
cd gmu-hackathon-siem-dashboard

# Install all dependencies (frontend + backend)
npm install
```

### Development (both frontend + backend concurrently)

```bash
npm run dev
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:3001
- WebSocket: ws://localhost:3001

### Production Build

```bash
npm run build
npm start  # starts backend serving on port 3001
```

---

## Project Structure

```
gmu-hackathon-siem-dashboard/
├── backend/
│   ├── src/
│   │   ├── index.ts          # Express + Socket.io server
│   │   ├── logGenerator.ts   # Realistic security event generator
│   │   ├── threatDetector.ts # Rules-based threat detection engine
│   │   └── types.ts          # Shared TypeScript types
│   ├── package.json
│   └── tsconfig.json
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── charts/       # Recharts wrappers (Area, Pie, Bar, Radar)
│   │   │   ├── AlertCard.tsx # Alert card with actions
│   │   │   ├── Header.tsx    # Top navigation bar
│   │   │   ├── LogTable.tsx  # Reusable log event table
│   │   │   ├── Sidebar.tsx   # Navigation sidebar
│   │   │   ├── SeverityBadge.tsx
│   │   │   └── StatCard.tsx  # KPI metric card
│   │   ├── hooks/
│   │   │   └── useSocket.ts  # Socket.io React hook
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx # Overview page
│   │   │   ├── LiveFeed.tsx  # Real-time log stream
│   │   │   ├── Alerts.tsx    # Alert management
│   │   │   └── Rules.tsx     # Detection rules viewer
│   │   ├── types/index.ts    # Frontend TypeScript types
│   │   ├── App.tsx           # Root component + state management
│   │   ├── index.css         # Tailwind + custom styles
│   │   └── main.tsx
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── tsconfig.json
│
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
└── package.json              # Root workspace config
```

---

## API Reference

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/logs?limit=200` | Recent log events |
| GET | `/api/alerts` | All alerts |
| GET | `/api/stats` | Current statistics |
| PATCH | `/api/alerts/:id` | Update alert status |

### WebSocket Events

| Event | Direction | Payload |
|-------|-----------|---------|
| `init` | Server → Client | `{ logs, alerts, stats }` — initial data dump |
| `log` | Server → Client | `LogEvent` — new security event |
| `alert` | Server → Client | `Alert` — new threat alert |
| `alert_updated` | Server → Client | `Alert` — alert status change |
| `stats` | Server → Client | `Stats` — updated statistics (every 5s) |

---

## Architecture Decisions

**Why monorepo?** Single `npm install` from root sets up everything. Shared TypeScript types between frontend and backend reduce duplication.

**Why Socket.io over raw WebSocket?** Automatic reconnection, fallback to polling, and room-based broadcasting for future multi-tenant support.

**Why in-memory store?** Hackathon scope — swappable for Elasticsearch, ClickHouse, or PostgreSQL TimescaleDB in production.

**Why no auth?** By design for demo. Production would add JWT + RBAC.

---

## Future Roadmap

- [ ] Persistent storage (Elasticsearch / ClickHouse)
- [ ] Real log ingestion via syslog, Filebeat, or Fluent Bit
- [ ] GeoIP map visualization (D3 world map)
- [ ] Threat intelligence feed integration (AbuseIPDB, VirusTotal)
- [ ] User authentication and RBAC
- [ ] Email / PagerDuty / Slack alerting integrations
- [ ] Custom rule builder with Sigma rule support
- [ ] Multi-tenant architecture

---

## License

[MIT](LICENSE) © 2026 GMU Hackathon Team

---

## Acknowledgments

- [MITRE ATT&CK Framework](https://attack.mitre.org/) — threat classification
- [Recharts](https://recharts.org/) — composable charting library
- [Lucide Icons](https://lucide.dev/) — clean SVG icons
- [Tailwind CSS](https://tailwindcss.com/) — utility-first styling
- [Socket.io](https://socket.io/) — real-time bidirectional events
