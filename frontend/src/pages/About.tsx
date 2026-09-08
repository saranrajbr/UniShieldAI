import { ExternalLink, BookOpen, ShieldCheck } from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";

const SECTIONS = [
  {
    title: "What UniShield AI does",
    items: [
      "Ingests unidirectional or asymmetric IP flows (PCAP replay, REST push, live Scapy capture, NetFlow/IPFIX/sFlow).",
      "Reconstructs bidirectional tuples and extracts both statistical and cyber-enriched features.",
      "Runs rule-based detectors (DDoS amplification, DNS tunneling, scans, brute-force…) plus a supervised ML classifier and an anomaly detector.",
      "Fuses all source scores into a single risk score, assigns a severity, and emits a live alert to a read-only SOC console.",
    ],
  },
  {
    title: "Deployment architecture",
    items: [
      "Backend: Python FastAPI (this workspace: backend/) — runs on port 8000 by default.",
      "Frontend: React 18 + Vite + Tailwind v4 (frontend/) — dev proxy to port 8000, production build served via any static host.",
      "WireGuard tunnel: securely connects the sensor VM (Laptop 2) to Laptop 1 so the engine can receive live sensor feeds over the encrypted link.",
      "All sources feed a single pipeline — no separate batch, no write-back, no active blocking.",
    ],
  },
  {
    title: "This console is read-only",
    items: [
      "No Block, Isolate or mitigation actions are performed from the frontend — this is intentional.",
      "Any “recommended action” shown here is advisory and must be executed in your actual network infrastructure.",
      "The goal is to detect and explain, not to react autonomously.",
    ],
  },
];

export default function About() {
  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title="PS 26145 · About"
        subtitle="Smart India Hackathon 2026 · AI-based detection of unidirectional (one-way) IP traffic."
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 flex flex-col gap-4">
          {SECTIONS.map((section) => (
            <Card key={section.title} title={section.title}>
              <ul className="space-y-2.5 text-[12.5px] text-[#94A3B8] leading-relaxed">
                {section.items.map((t) => (
                  <li key={t} className="flex gap-2.5">
                    <span className="text-[#34D399] mt-0.5">✓</span>
                    {t}
                  </li>
                ))}
              </ul>
            </Card>
          ))}

          <Card title="Detection categories (current run)">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-[12px]">
              {[
                "Distributed DoS (DDoS)",
                "Denial of Service (DoS)",
                "DNS Tunneling",
                "C2 Beaconing",
                "Port Scanning",
                "Data Exfiltration",
                "Brute Force",
                "Malware Communication",
                "Malicious IPs / suspicious traffic",
                "Reconnaissance",
              ].map((t) => (
                <div key={t} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06]">
                  <ShieldCheck size={13} className="text-[#6BCB77] shrink-0" />
                  <span className="text-[#CBD5E1]">{t}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <div className="flex flex-col gap-4">
          <Card title="Quick reference" subtitle="Environment defaults for the running instance">
            <div className="flex flex-col gap-2.5 text-[12px]">
              <KV k="Backend URL" v="http://localhost:8000" />
              <KV k="Frontend dev" v="http://localhost:5173" />
              <KV k="REST alerts" v="/api/v1/alerts" />
              <KV k="Live feed (WS)" v="ws://localhost:8000/ws/alerts" />
              <KV k="NetFlow listener" v="UDP :2055" />
              <KV k="WireGuard tunnel" v="172.16.250.1 ↔ 172.16.250.2" />
              <KV k="Feature vector size" v="20 fields" />
            </div>
          </Card>

          <Card title="Documentation" subtitle="Companion docs in the repository root: docs/">
            <div className="flex flex-col gap-2">
              {[
                { name: "Architecture", path: "/docs/architecture.md" },
                { name: "API reference", path: "/docs/api.md" },
                { name: "Detection & rules", path: "/docs/detection.md" },
                { name: "Deployment", path: "/docs/deployment.md" },
              ].map((doc) => (
                <a
                  key={doc.name}
                  href={doc.path}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-white/[0.03] border border-white/[0.06] hover:bg-white/[0.06] hover:border-white/[0.12] transition-colors group"
                >
                  <BookOpen size={14} strokeWidth={1.75} className="text-[#64748B] group-hover:text-[#A78BFA]" />
                  <span className="text-[12.5px] font-medium text-[#CBD5E1]">{doc.name}</span>
                  <ExternalLink size={11} strokeWidth={2} className="ml-auto text-[#334155] group-hover:text-[#64748B]" />
                </a>
              ))}
            </div>
          </Card>

          <Card title="Project team" subtitle="Built for SIH 2026 · PS 26145">
            <p className="text-[12px] text-[#94A3B8] leading-relaxed">
              UniShield AI is a prototype security console built specifically for this problem statement.
              It is designed to be demonstrable on two laptops, a virtual network, and real or replayed unidirectional traffic.
            </p>
          </Card>
        </div>
      </div>
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-start gap-3">
      <span className="w-[110px] text-[10.5px] text-[#64748B] uppercase tracking-wider shrink-0">{k}</span>
      <span className="text-[12px] font-mono font-medium text-[#CBD5E1] break-all">{v}</span>
    </div>
  );
}