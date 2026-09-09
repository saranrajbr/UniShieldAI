import { useMemo, useState } from "react";
import { Search, Inbox } from "lucide-react";
import { Link } from "react-router-dom";
import { useEngine } from "../store/engine";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { SeverityBadge } from "../components/alerts/SeverityBadge";
import { ThreatBadge } from "../components/alerts/ThreatBadge";
import { FlowPair, StatusChip } from "../components/alerts/AlertRow";
import { EmptyState, SearchEmptyState } from "../components/alerts/EmptyState";
import { severityMeta } from "../lib/threats";
import { humanThreatType, timeAgo, type Alert } from "../lib/api";
import { cn } from "../lib/cn";

type StatusTab = "all" | "new" | "investigating" | "resolved" | "ignored";

function statusOf(a: Alert): Exclude<StatusTab, "all"> {
  if (a.status === "resolved") return "resolved";
  if (a.status === "ignored") return "ignored";
  if (a.detection_sources && a.detection_sources.length >= 2) return "investigating";
  return "new";
}

const TABS: { id: StatusTab; label: string }[] = [
  { id: "all", label: "All" },
  { id: "new", label: "New" },
  { id: "investigating", label: "Investigating" },
  { id: "resolved", label: "Resolved" },
  { id: "ignored", label: "Ignored" },
];

export default function Alerts() {
  const alerts = useEngine((s) => s.alerts);
  const gotData = useEngine((s) => s.gotData);
  const sources = useEngine((s) => s.sources);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [threat, setThreat] = useState("all");
  const [tab, setTab] = useState<StatusTab>("all");

  const liveBySrc = useMemo(() => {
    const m = new Map<string, boolean>();
    sources.forEach((s) => s.active && m.set(s.ip, true));
    return m;
  }, [sources]);

  const threatTypes = useMemo(
    () => [...new Set(alerts.map((a) => a.threat_type))].sort(),
    [alerts]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return alerts.filter((a) => {
      if (severity !== "all" && a.severity !== severity) return false;
      if (threat !== "all" && a.threat_type !== threat) return false;
      if (tab !== "all" && statusOf(a) !== tab) return false;
      if (!q) return true;
      return (
        a.src_ip.toLowerCase().includes(q) ||
        a.dst_ip.toLowerCase().includes(q) ||
        (a.protocol ?? "").toLowerCase().includes(q) ||
        humanThreatType(a.threat_type).toLowerCase().includes(q) ||
        a.alert_id.toLowerCase().includes(q)
      );
    });
  }, [alerts, severity, threat, tab, query]);

  const counts = useMemo(() => {
    const c: Record<StatusTab, number> = { all: alerts.length, new: 0, investigating: 0, resolved: 0, ignored: 0 };
    alerts.forEach((a) => (c[statusOf(a)] += 1));
    return c;
  }, [alerts]);

  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title="Security Alerts"
        subtitle="Every detection the engine raised, ranked by severity — click a row to investigate the evidence."
      />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2.5 mb-4">
        <div className="flex items-center gap-2 flex-1 min-w-[240px] max-w-md h-10 px-3 rounded-lg bg-white/[0.03] border border-white/[0.08] focus-within:border-[#7C5CFC]/50 transition-colors">
          <Search size={14} className="text-[#64748B] shrink-0" strokeWidth={2} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by IP, protocol, threat…"
            className="bg-transparent border-none outline-none text-[13px] text-white placeholder:text-[#475569] flex-1"
            aria-label="Search alerts"
          />
        </div>
        <Select
          value={severity}
          onChange={setSeverity}
          label="Severity"
          options={[
            { value: "all", label: "All severities" },
            { value: "critical", label: "Critical" },
            { value: "high", label: "High" },
            { value: "medium", label: "Medium" },
            { value: "low", label: "Low" },
          ]}
        />
        <Select
          value={threat}
          onChange={setThreat}
          label="Threat"
          options={[
            { value: "all", label: "All threats" },
            ...threatTypes.map((t) => ({ value: t, label: humanThreatType(t) })),
          ]}
        />
        {/* Status tabs */}
        <div className="flex items-center p-1 rounded-lg bg-white/[0.03] border border-white/[0.06] overflow-x-auto thin-scroll">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "px-3 h-8 rounded-md text-[12px] font-medium whitespace-nowrap transition-all",
                tab === t.id ? "bg-white/[0.09] text-white" : "text-[#94A3B8] hover:text-[#CBD5E1]"
              )}
            >
              {t.label}
              <span className="ml-1.5 text-[10px] tabular-nums opacity-70">{counts[t.id]}</span>
            </button>
          ))}
        </div>
      </div>

      <Card>
        {!gotData ? (
          <EmptyState mode="offline" />
        ) : filtered.length === 0 ? (
          query.trim() || severity !== "all" || threat !== "all" || tab !== "all" ? (
            <SearchEmptyState query={query.trim() || "current filters"} />
          ) : (
            <EmptyState
              mode="empty"
              icon={Inbox}
              title="No alerts yet"
              hint="The engine has not raised any alerts in the current window."
            />
          )
        ) : (
          <div className="flex flex-col">
            {/* Column headers */}
            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/[0.06] text-[10px] uppercase tracking-[0.12em] text-[#475569]">
              <span className="w-[84px] shrink-0">Severity</span>
              <span className="flex-1">Threat</span>
              <span className="hidden xl:inline-flex flex-1">Source → Destination</span>
              <span className="hidden sm:inline-flex w-[110px]">Evidence</span>
              <span className="hidden md:block w-[76px]">State</span>
              <span className="w-[92px] text-right">Detected</span>
            </div>
            {filtered.slice(0, 120).map((a) => (
              <Link
                key={a.alert_id}
                to={`/investigation/${a.alert_id}`}
                className="flex items-center gap-3 px-4 min-h-[48px] hover:bg-white/[0.03] transition-colors border-b border-white/[0.04] group"
              >
                <SeverityBadge severity={a.severity} className="w-[84px] justify-center shrink-0" />
                <span className="flex-1 min-w-0">
                  <span className="flex items-center gap-2">
                    <ThreatBadge type={a.threat_type} />
                    <span
                      className="text-[10px] font-semibold uppercase tracking-wider hidden md:inline"
                      style={{ color: severityMeta(a.severity).color }}
                    >
                      risk {Math.round(a.risk_score * 100)}%
                    </span>
                  </span>
                </span>
                <FlowPair
                  src={a.src_ip}
                  dst={a.dst_ip}
                  srcPort={a.src_port}
                  dstPort={a.dst_port}
                  protocol={a.protocol}
                  className="hidden xl:inline-flex flex-1 min-w-0"
                />
                <span className="hidden sm:flex w-[110px] gap-1 flex-wrap">
                  {(a.detection_sources ?? []).slice(0, 2).map((s) => (
                    <span
                      key={s}
                      className="px-1.5 h-[18px] rounded text-[9.5px] font-medium bg-white/[0.05] text-[#94A3B8] border border-white/[0.06] flex items-center"
                    >
                      {s.replace(/_/g, " ")}
                    </span>
                  ))}
                </span>
                <span className="hidden md:flex w-[76px] shrink-0 justify-start">
                  <StatusChip live={liveBySrc.has(a.src_ip)} />
                </span>
                <span className="w-[92px] text-right text-[11px] text-[#64748B] tabular-nums whitespace-nowrap shrink-0">
                  {timeAgo(a.timestamp)}
                </span>
              </Link>
            ))}
            {filtered.length > 120 && (
              <p className="px-4 py-3 text-[11px] text-[#475569]">
                Showing first 120 of {filtered.length} matching alerts — the engine keeps the most recent 200.
              </p>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

function Select({
  value,
  onChange,
  label,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="relative">
      <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[10px] uppercase tracking-wider text-[#475569] pointer-events-none">
        {label}
      </span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-10 pl-14 pr-3 rounded-lg bg-white/[0.03] border border-white/[0.08] text-[13px] text-[#CBD5E1] outline-none appearance-none cursor-pointer hover:border-white/[0.16] transition-colors focus:border-[#7C5CFC]/50"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-[#12141F]">
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}