import { Cpu } from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { StatCard } from "../components/ui/StatCard";
import { EmptyState } from "../components/alerts/EmptyState";
import { useEngine } from "../store/engine";
import { formatNumber, type EngineMetrics, type RuntimeMetrics } from "../lib/api";

const PIPELINE = [
  { key: "ingest", label: "Ingestion", color: "#38BDF8", desc: "REST flows + NetFlow/IPFIX/sFlow listener + live Scapy capture" },
  { key: "features", label: "Feature extraction", color: "#7C5CFC", desc: "Derives statistical + cyber features from raw flow records" },
  { key: "rules", label: "Rule engine", color: "#A78BFA", desc: "Fires heuristic thresholds and pattern rules (DDoS, scans…)" },
  { key: "ml", label: "ML inference", color: "#FF9F43", desc: "Supervised classifier + anomaly detector evaluate every feature vector" },
  { key: "decision", label: "Decision fusion", color: "#FFD93D", desc: "Fuses scores and decides advisory severity" },
  { key: "alert", label: "Alerting", color: "#FF4D6A", desc: "Deduplicates and emits the final alert payload to the WS feed and REST API" },
];

function Box({ color, title, value, hint }: { color: string; title: string; value: string; hint?: string }) {
  return (
    <div
      className="flex flex-col gap-1 rounded-xl p-3 border"
      style={{ borderColor: `${color}2E`, background: `${color}0A` }}
    >
      <span className="text-[10px] uppercase tracking-widest" style={{ color }}>
        {title}
      </span>
      <span className="text-[14px] font-semibold text-white tabular-nums">{value}</span>
      {hint && <span className="text-[10.5px] text-[#64748B]">{hint}</span>}
    </div>
  );
}

export default function Engine() {
  const metrics = useEngine((s) => s.metrics);
  const engine = useEngine((s) => s.engine);
  const engines = useEngine((s) => s.engines);
  const models = useEngine((s) => s.models);
  const rules = useEngine((s) => s.rules);
  const gotData = useEngine((s) => s.gotData);

  if (!gotData && !metrics) {
    return (
      <div className="p-5 md:p-6">
        <PageHeader title="Detection Engine" subtitle="Waiting for the engine to respond…" />
        <EmptyState mode="offline" />
      </div>
    );
  }

  const fe = engine?.flow_export;

  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title="Detection Engine"
        subtitle="Live pipeline, rules and models powering the PS 26145 AI detector — read-only operational console."
      />

      {/* Health */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <StatCard label="Uptime" value={fmtDur(metrics?.uptime_sec)} icon={Cpu} accent="#6BCB77" />
        <StatCard label="CPU" value={metrics ? `${metrics.cpu_percent.toFixed(1)}%` : "—"} icon={Cpu} accent="#38BDF8" />
        <StatCard label="Memory" value={metrics ? `${(metrics.memory_mb / 1024).toFixed(2)} GB` : "—"} icon={Cpu} accent="#A78BFA" />
        <StatCard
          label="Errors / queue peak"
          value={metrics ? `${formatNumber(metrics.processing_errors)}` : "—"}
          icon={Cpu}
          accent="#FF9F43"
          hint={`queue high-watermark ${metrics ? formatNumber(metrics.queue_high_watermark) : "—"}`}
        />
      </div>

      {/* Pipeline */}
      <Card
        title="Processing pipeline"
        subtitle="Each flow passes through every stage — the counts are cumulative since engine start."
        className="mb-4"
      >
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          {PIPELINE.map((stage) => (
            <Box
              key={stage.key}
              color={stage.color}
              title={stage.label}
              value={pipelineVal(stage.key, metrics, fe, engines, engine)}
              hint={stage.desc}
            />
          ))}
        </div>
      </Card>

      {/* Rules + models */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card title="Rules loaded" subtitle={`Total rule count ${rules?.count ?? engines?.rules?.loaded ?? "—"} — broken down by category`}>
          <RuleBars categories={engines?.rules?.categories ?? {}} />
        </Card>

        <Card title="ML models">
          {models ? (
            <div className="flex flex-col gap-3">
              {Object.entries(models.paths).map(([k, v]) => (
                <div key={k} className="flex flex-col rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                  <span className="text-[10px] uppercase tracking-wider text-[#64748B]">{k.replace(/_/g, " ")}</span>
                  <span className="text-[11px] font-mono text-[#94A3B8] truncate mt-0.5" title={v}>{v}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[12px] text-[#64748B]">Model info not yet loaded.</p>
          )}
        </Card>

        <Card title="Decision configuration">
          <div className="flex flex-col gap-3">
            <div className="flex flex-col rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <span className="text-[10px] uppercase tracking-wider text-[#64748B]">Threat decision threshold</span>
              <span className="text-[14px] font-semibold text-white tabular-nums mt-1">
                {engines?.decision?.threshold != null ? engines.decision.threshold.toFixed(3) : "—"}
              </span>
              <p className="text-[11px] text-[#475569] mt-1">
                Flows scoring above this value are classified as threats. The fused score is then mapped to severity.
              </p>
            </div>
            <div className="flex flex-col rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <span className="text-[10px] uppercase tracking-wider text-[#64748B]">is_threat_ground_truth</span>
              <span className="text-[14px] font-semibold text-white tabular-nums mt-1">
                {engines?.decision?.is_threat_gt ?? "—"}
              </span>
              <p className="text-[11px] text-[#475569] mt-1">
                Ground-truth label used during training / validation (informational only in the live engine).
              </p>
            </div>
          </div>
        </Card>
      </div>

      {/* NetFlow listener */}
      <Card
        title="NetFlow / IPFIX / sFlow listener"
        subtitle={fe ? `Listening on ${fe.udp_host}:${fe.udp_port}` : "Not loaded"}
        className="mt-4"
      >
        {fe ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatBox label="Datagrams received" value={formatNumber(fe.datagrams_received)} color="#38BDF8" />
            <StatBox label="Flow records parsed" value={formatNumber(fe.records_parsed)} color="#6BCB77" />
            <StatBox label="Records rejected" value={formatNumber(fe.records_rejected)} color="#FF4D6A" />
            <StatBox label="Endpoint" value={`${fe.udp_host}:${fe.udp_port}`} color="#94A3B8" />
          </div>
        ) : (
          <p className="text-[12px] text-[#64748B]">
            The NetFlow listener is configured via the backend environment. Start the backend with NETFLOW_UDP_PORT to enable it.
          </p>
        )}
      </Card>
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div
      className="flex flex-col rounded-xl p-3 border"
      style={{ borderColor: `${color}2E`, background: `${color}0A` }}
    >
      <span className="text-[10px] uppercase tracking-widest" style={{ color }}>{label}</span>
      <span className="text-[15px] font-semibold text-white tabular-nums mt-1">{value}</span>
    </div>
  );
}

function RuleBars({
  categories,
}: {
  categories: Record<string, number>;
}) {
  const max = Math.max(...Object.values(categories), 1);
  return (
    <div className="flex flex-col gap-2.5">
      {Object.entries(categories)
        .sort(([, a], [, b]) => Number(b) - Number(a))
        .map(([cat, count]) => (
          <div key={cat} className="flex items-center gap-3">
            <span className="w-[110px] text-[11px] text-[#94A3B8] text-right truncate" title={cat}>
              {cat.replace(/_/g, " ")}
            </span>
            <div className="flex-1 h-2 rounded-full bg-white/[0.06] overflow-hidden">
              <div
                className="h-full rounded-full bg-[#A78BFA]"
                style={{ width: `${Math.max(4, Math.round((count / max) * 100))}%` }}
              />
            </div>
            <span className="w-8 text-right text-[10.5px] font-semibold tabular-nums text-[#CBD5E1]">{count}</span>
          </div>
        ))}
      {Object.keys(categories).length === 0 && (
        <p className="text-[12px] text-[#64748B]">Rule categories not yet loaded.</p>
      )}
    </div>
  );
}

function pipelineVal(key: string, metrics: RuntimeMetrics | null, fe: EngineMetrics["flow_export"] | undefined, engines: import("../lib/api").DetectionEngines | null, engine: EngineMetrics | null): string {
  if (!metrics && !engine) return "—";
  switch (key) {
    case "ingest":
      return fe ? `${formatNumber(fe.records_parsed)} flows` : "—";
    case "features":
      return metrics ? `${formatNumber(metrics.flows_processed)} vectors` : "—";
    case "rules":
      return engines ? `${engines.rules.loaded} loaded` : "—";
    case "ml":
      return metrics ? `${formatNumber(metrics.ml_inferences)} inferences` : "—";
    case "decision":
      return engines?.decision?.threshold != null ? `threshold ${engines.decision.threshold.toFixed(3)}` : "—";
    case "alert":
      return metrics ? `${formatNumber(metrics.alerts_raised)} raised` : "—";
    default:
      return "—";
  }
}

function fmtDur(sec?: number): string {
  if (sec == null) return "—";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}