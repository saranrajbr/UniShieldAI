import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import {
  Gauge,
  Route,
  Waves,
  ShieldAlert,
  BrainCircuit,
  FileClock,
  Radio,
} from "lucide-react";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Cell,
  PieChart,
  Pie,
} from "recharts";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { StatCard } from "../components/ui/StatCard";
import { AlertRow, StatusChip } from "../components/alerts/AlertRow";
import { EmptyState } from "../components/alerts/EmptyState";
import { severityMeta } from "../lib/threats";
import { threatMeta } from "../lib/threats";
import {
  formatNumber,
  humanThreatType,
  type EngineMetrics,
  type RuntimeMetrics,
} from "../lib/api";
import type { SourceActivity } from "../store/engine";
import { useEngine } from "../store/engine";

const PIE_COLORS = ["#7C5CFC", "#FF4D6A", "#FF9F43", "#FFD93D", "#6BCB77", "#38BDF8"];

function tooltipStyle() {
  return {
    borderRadius: 8,
    border: "1px solid rgba(255,255,255,0.1)",
    background: "#12141F",
    color: "#CBD5E1",
    fontSize: 12,
  };
}

export default function Overview() {
  const alerts = useEngine((s) => s.alerts);
  const stats = useEngine((s) => s.stats);
  const metrics = useEngine((s) => s.metrics);
  const traffic = useEngine((s) => s.trafficMetrics);
  const engine = useEngine((s) => s.engine);
  const history = useEngine((s) => s.history);
  const gotData = useEngine((s) => s.gotData);
  const lastUpdated = useEngine((s) => s.lastUpdated);
  const sources = useEngine((s) => s.sources);

  const liveBySrc = useMemo(() => {
    const m = new Map<string, boolean>();
    sources.forEach((s) => s.active && m.set(s.ip, true));
    return m;
  }, [sources]);
  const activeAttacks = useMemo(
    () => sources.filter((s) => s.active && s.alertCount > 0),
    [sources]
  );
  const endedAttacks = useMemo(
    () => sources.filter((s) => !s.active && s.alertCount > 0),
    [sources]
  );

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      const k = a.severity as keyof typeof c;
      if (k in c) c[k] += 1;
    });
    return c;
  }, [alerts]);

  const threatDist = useMemo(() => {
    const m = new Map<string, number>();
    alerts.forEach((a) => m.set(a.threat_type, (m.get(a.threat_type) ?? 0) + 1));
    const rows = [...m.entries()]
      .map(([type, value]) => ({ name: humanThreatType(type), key: type, value }))
      .sort((a, b) => b.value - a.value);
    const top = rows.slice(0, 6);
    const rest = rows.slice(6).reduce((acc, r) => acc + r.value, 0);
    if (rest > 0) top.push({ name: "Other", key: "other", value: rest });
    return top;
  }, [alerts]);

  const liveRate = metrics ? `${formatNumber(metrics.flow_rate_fps)}/s` : "—";
  const pps = traffic ? `${formatNumber(traffic.packets_per_sec)}/s` : "—";

  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title="Security Overview"
        subtitle={
          lastUpdated
            ? `Live engine snapshot · last refreshed ${new Date(lastUpdated).toLocaleTimeString("en-US", { hour12: false })} · alerts window ${stats?.window ?? ""}`
            : "UniShield AI · AI detection for unidirectional traffic"
        }
      />

      {/* KPI row */}
      {!gotData && !metrics ? (
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <StatCard key={i} label="Loading" value="—" icon={Gauge} loading />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          <StatCard label="Ingest rate" value={liveRate} icon={Gauge} accent="#38BDF8" hint={pps && `Packets ${pps}`} />
          <StatCard
            label="Flows processed"
            value={metrics ? formatNumber(metrics.flows_processed) : "—"}
            icon={Route}
            accent="#7C5CFC"
            hint="since engine start"
          />
          <StatCard
            label="Active flows"
            value={stats ? `${stats.active_flows}` : "—"}
            icon={Waves}
            accent="#6BCB77"
            hint={`${stats?.connections ?? 0} conns · 60s window`}
          />
          <StatCard
            label="Alerts raised"
            value={metrics ? formatNumber(metrics.alerts_raised) : "—"}
            icon={ShieldAlert}
            accent="#FF4D6A"
            hint={`${metrics ? formatNumber(metrics.rules_fired) : 0} rule fires`}
          />
          <StatCard
            label="ML inferences"
            value={metrics ? formatNumber(metrics.ml_inferences) : "—"}
            icon={BrainCircuit}
            accent="#FF9F43"
            hint="supervised + anomaly"
          />
          <StatCard
            label="Queue / errors"
            value={`${queue(metrics, engine)}`}
            icon={FileClock}
            accent="#94A3B8"
            hint={`${metrics ? formatNumber(metrics.queue_high_watermark) : 0} peak · ${metrics?.processing_errors ?? 0} err`}
          />
        </div>
      )}

      {/* Live attack tracking */}
      <Card
        title="Active threat sources"
        subtitle={
          activeAttacks.length
            ? `${activeAttacks.length} source${activeAttacks.length === 1 ? "" : "s"} currently under active threat`
            : endedAttacks.length
              ? "No live attacks right now — recent sources shown below"
              : "Monitoring traffic continuously — new threats appear here instantly"
        }
        className="mt-4"
        action={
          activeAttacks.length ? (
            <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#FF8CA0] live-source">
              <span className="w-1.5 h-1.5 rounded-full bg-[#FF4D6A] live-source" /> Live
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[#6BCB77]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#6BCB77]" /> Monitoring
            </span>
          )
        }
      >
        {activeAttacks.length === 0 && endedAttacks.length === 0 ? (
          <EmptyState
            title="No tracked sessions"
            hint="When flows arrive, an attacking source lights up here and a popup appears. Once it stops sending, it moves to Recently ended."
          />
        ) : (
          <div className="flex flex-col -mx-5 -mb-5">
            {activeAttacks.slice(0, 8).map((s) => (
              <AttackRow key={s.ip} s={s} />
            ))}
            {endedAttacks.length > 0 && (
              <div className="px-5 py-2.5 border-t border-white/[0.05] bg-white/[0.01]">
                <p className="text-[10px] uppercase tracking-[0.14em] text-[#475569] mb-1.5">
                  Recently ended
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {endedAttacks.slice(0, 6).map((s) => (
                    <span
                      key={s.ip}
                      className="inline-flex items-center gap-1.5 px-2 h-[22px] rounded-md bg-white/[0.03] border border-white/[0.06] text-[10.5px] text-[#94A3B8] font-medium"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-white/[0.2]" />
                      <span className="font-mono">{s.ip}</span>
                      <span className="text-[#64748B]">
                        {threatMeta(s.threat).label}
                      </span>
                      <StatusChip live={false} />
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Charts + severity panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mt-4">
        <Card
          title="Ingest & detection trend"
          subtitle="Flow rate (per second) and cumulative alerts — continuous 5s samples, last ~2 minutes"
          className="lg:col-span-2"
        >
          {history.length < 2 ? (
            <div className="flex items-center justify-center h-[220px]">
              <EmptyState
                title="Collecting trend samples"
                hint="The trend chart builds as the engine processes traffic."
              />
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={history} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gFlow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38BDF8" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#38BDF8" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gAlerts" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#FF4D6A" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#FF4D6A" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="t"
                  tick={{ fill: "#64748B", fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={42}
                />
                <YAxis
                  tick={{ fill: "#64748B", fontSize: 10 }}
                  tickLine={false}
                  axisLine={false}
                  tickFormatter={(v) => formatNumber(v)}
                />
                <Tooltip contentStyle={tooltipStyle()} />
                <Area type="monotone" dataKey="flows" name="Flow rate /s" stroke="#38BDF8" strokeWidth={1.75} fill="url(#gFlow)" />
                <Area type="monotone" dataKey="alerts" name="Alerts (cum.)" stroke="#FF4D6A" strokeWidth={1.75} fill="url(#gAlerts)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </Card>

        <Card
          title="Threat posture"
          subtitle="Open alerts by type & severity (analyzed window)"
        >
          <div className="flex flex-col h-[220px]">
            <div className="flex-1 relative">
              {threatDist.length === 0 ? (
                <div className="flex items-center justify-center h-full">
                  <EmptyState title="No detections in window" hint="Threats are classified here as flows are analyzed." />
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={threatDist}
                      dataKey="value"
                      nameKey="name"
                      innerRadius="62%"
                      outerRadius="88%"
                      paddingAngle={2}
                      stroke="none"
                    >
                      {threatDist.map((_, i) => (
                        <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle()} />
                  </PieChart>
                </ResponsiveContainer>
              )}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="text-[20px] font-semibold text-white tabular-nums">
                  {alerts.length}
                </span>
                <span className="text-[10px] uppercase tracking-wider text-[#64748B]">
                  alerts
                </span>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-1.5 mt-2">
              {(["critical", "high", "medium", "low"] as const).map((k) => (
                <div
                  key={k}
                  className="flex flex-col items-center rounded-lg py-1.5 border"
                  style={{
                    borderColor: `${severityMeta(k).color}2E`,
                    background: severityMeta(k).bg,
                  }}
                >
                  <span
                    className="text-[15px] font-semibold tabular-nums"
                    style={{ color: severityMeta(k).color }}
                  >
                    {sevCounts[k]}
                  </span>
                  <span className="text-[9px] uppercase tracking-wider opacity-80">
                    {severityMeta(k).label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Feed + sources */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mt-4">
        <Card
          title="Recent detections"
          subtitle="Latest classified threats — click to open the investigation"
          className="lg:col-span-2"
          action={
            <Link
              to="/alerts"
              className="flex items-center gap-1.5 text-[12px] font-medium text-[#A78BFA] hover:text-[#C4B5FD] transition-colors"
            >
              Open alert queue <ArrowRight size={13} strokeWidth={2} />
            </Link>
          }
        >
          {alerts.length === 0 ? (
            <EmptyState
              title="No detections yet"
              hint="Once the engine processes unidirectional traffic, detected threats appear here ranked by severity."
            />
          ) : (
            <div className="-mx-5 -mb-5">
              {alerts.slice(0, 8).map((a) => (
                <AlertRow key={a.alert_id} alert={a} live={liveBySrc.has(a.src_ip)} />
              ))}
            </div>
          )}
        </Card>

        <div className="flex flex-col gap-4">
          <Card title="Network sources" subtitle="Active ingest channels feeding the engine">
            <div className="flex flex-col gap-2.5">
              <SourceRow
                icon={Radio}
                name="Live & rest sensor"
                value={engine?.flow_export ? "active" : "polling"}
                ok
              />
              <SourceRow
                icon={Waves}
                name="NetFlow / IPFIX / sFlow"
                value={
                  engine?.flow_export
                    ? `${formatNumber(engine.flow_export.records_parsed)} flows`
                    : "listener: 2055"
                }
              />
              <SourceRow
                icon={Gauge}
                name="Window drift"
                value={stats ? `${formatNumber(stats.processed)} processed` : "—"}
              />
            </div>
          </Card>
          <Card title="What am I looking at?" subtitle="PS 26145 · read-only analyzer">
            <ul className="text-[12px] text-[#94A3B8] leading-relaxed space-y-2">
              {[
                "Classifies every flow using rules + ML (DDoS amplification, DNS tunneling, C2, scans…).",
                "Detections are advisory — this console only raises alarms, it never blocks or isolates.",
                "Best signals to watch: Ingest rate, Alerts raised, and severity spikes in the posture panel.",
              ].map((t) => (
                <li key={t} className="flex gap-2">
                  <span className="text-[#6BCB77] mt-0.5">✓</span>
                  {t}
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}

function queue(metrics: RuntimeMetrics | null, engineEngine: EngineMetrics | null): string {
  if (metrics) return `${formatNumber(metrics.queue_high_watermark)}`;
  if (engineEngine) return `${formatNumber(engineEngine.flows_queued)}`;
  return "—";
}

function fmtDur(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${s % 60}s`;
}

function AttackRow({ s }: { s: SourceActivity }) {
  const [, force] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => force((v) => v + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  const meta = severityMeta(s.severity);
  const tmeta = threatMeta(s.threat);
  return (
    <div className="flex items-center gap-3 px-5 min-h-[52px] border-b border-white/[0.04]">
      <span
        className="w-2.5 h-2.5 rounded-full shrink-0 live-source"
        style={{ background: meta.color, boxShadow: `0 0 8px ${meta.color}` }}
      />
      <span className="flex flex-col justify-center min-w-0 flex-1">
        <span className="flex items-center gap-2 text-[12.5px] font-semibold text-white">
          <span className="font-mono">{s.ip}</span>
          <span className="text-[#475569]">→</span>
          <span className="font-mono text-[#94A3B8]">{s.dst || "…"}</span>
        </span>
        <span className="text-[10.5px] text-[#64748B] truncate">
          {tmeta.label} · {s.alertCount} alert{s.alertCount === 1 ? "" : "s"}
        </span>
      </span>
      <div className="flex items-center gap-2 shrink-0">
        <span className="text-[11px] text-[#CBD5E1] tabular-nums text-right">
          active {fmtDur(Date.now() - (s.firstSeen || s.lastSeen))}
        </span>
        <StatusChip live />
      </div>
      <span
        className="px-2 h-[20px] rounded-md text-[9.5px] font-bold uppercase tracking-wider shrink-0"
        style={{ color: meta.color, background: meta.bg }}
      >
        {meta.label}
      </span>
    </div>
  );
}

function SourceRow({
  icon: Icon,
  name,
  value,
  ok,
}: {
  icon: typeof Radio;
  name: string;
  value: string;
  ok?: boolean;
}) {
  return (
    <div className="flex items-center gap-3">
      <span
        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: ok ? "rgba(52,211,153,0.12)" : "rgba(255,217,61,0.12)", color: ok ? "#34D399" : "#FFD93D" }}
      >
        <Icon size={15} strokeWidth={1.75} />
      </span>
      <div className="min-w-0 flex-1 leading-tight">
        <p className="text-[12.5px] font-medium text-[#CBD5E1] truncate">{name}</p>
        <p className="text-[11px] text-[#64748B] truncate tabular-nums">{value}</p>
      </div>
      <span
        className="w-2 h-2 rounded-full shrink-0"
        style={{ background: ok ? "#34D399" : "#FFD93D" }}
      />
    </div>
  );
}