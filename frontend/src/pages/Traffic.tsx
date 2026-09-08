import { useMemo, useState } from "react";
import { Search, Waves, ArrowDownUp } from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/alerts/EmptyState";
import { FlowPair } from "../components/alerts/AlertRow";
import { useEngine } from "../store/engine";
import { formatBytes, formatNumber, type FlowRow } from "../lib/api";
import { cn } from "../lib/cn";

function FlagChip({ label, count }: { label: string; count: number }) {
  const active = count > 0;
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center h-[18px] min-w-[28px] px-1 rounded text-[9.5px] font-bold tabular-nums border",
        label === "SYN"
          ? active
            ? "bg-[#FF9F43]/12 text-[#FFC48A] border-[#FF9F43]/30"
            : "bg-white/[0.02] text-[#334155] border-white/[0.04]"
          : label === "RST"
            ? active
              ? "bg-[#FF4D6A]/12 text-[#FF8CA0] border-[#FF4D6A]/30"
              : "bg-white/[0.02] text-[#334155] border-white/[0.04]"
            : active
              ? "bg-white/[0.08] text-[#94A3B8] border-white/[0.1]"
              : "bg-white/[0.02] text-[#334155] border-white/[0.04]"
      )}
    >
      {count > 0 ? `${label}${count}` : "-"}
    </span>
  );
}

function PeriodicityBar({ value }: { value: number }) {
  const pct = Math.max(4, Math.min(100, Math.round(value * 100)));
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-white/[0.06] overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{
            width: `${pct}%`,
            background: value > 0.75 ? "#FF4D6A" : value > 0.4 ? "#FF9F43" : "#38BDF8",
          }}
        />
      </div>
      <span className="text-[10.5px] tabular-nums text-[#64748B] w-6">
        {(value * 100).toFixed(0)}%
      </span>
    </div>
  );
}

export default function Traffic() {
  const flows = useEngine((s) => s.flows);
  const gotData = useEngine((s) => s.gotData);
  const [query, setQuery] = useState("");
  const [proto, setProto] = useState("all");

  const protocols = useMemo(
    () => [...new Set(flows.map((f) => f.protocol))].sort(),
    [flows]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return flows
      .filter((f) => {
        if (proto !== "all" && f.protocol !== proto) return false;
        if (!q) return true;
        return (
          f.src_ip.toLowerCase().includes(q) ||
          f.dst_ip.toLowerCase().includes(q) ||
          f.flow_id.toLowerCase().includes(q)
        );
      })
      .sort((a, b) => b.last_seen - a.last_seen);
  }, [flows, proto, query]);

  const totals = useMemo(() => {
    return filtered.reduce(
      (acc, f) => {
        acc.packets += f.packet_count;
        acc.bytes += f.byte_count;
        acc.syn += f.syn_count;
        return acc;
      },
      { packets: 0, bytes: 0, syn: 0 }
    );
  }, [filtered]);

  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title="Live Traffic Flows"
        subtitle="Active bidirectional tuples reconstructed from unidirectional observations — protocol mix, size, flags and periodicity."
        actions={
          <div className="hidden md:flex items-center gap-6 px-4 h-10 rounded-lg bg-white/[0.03] border border-white/[0.06]">
            <div className="leading-tight">
              <span className="text-[11px] uppercase tracking-wider text-[#64748B] block">Flows</span>
              <span className="text-[14px] font-semibold text-white tabular-nums">{flows.length}</span>
            </div>
            <div className="leading-tight">
              <span className="text-[11px] uppercase tracking-wider text-[#64748B] block">Packets</span>
              <span className="text-[14px] font-semibold text-white tabular-nums">{formatNumber(totals.packets)}</span>
            </div>
            <div className="leading-tight">
              <span className="text-[11px] uppercase tracking-wider text-[#64748B] block">Bytes</span>
              <span className="text-[14px] font-semibold text-white tabular-nums">{formatBytes(totals.bytes)}</span>
            </div>
          </div>
        }
      />

      <div className="flex flex-wrap items-center gap-2.5 mb-4">
        <div className="flex items-center gap-2 flex-1 min-w-[240px] max-w-md h-10 px-3 rounded-lg bg-white/[0.03] border border-white/[0.08] focus-within:border-[#7C5CFC]/50 transition-colors">
          <Search size={14} className="text-[#64748B] shrink-0" strokeWidth={2} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by source or destination IP…"
            className="bg-transparent border-none outline-none text-[13px] text-white placeholder:text-[#475569] flex-1"
            aria-label="Filter flows"
          />
        </div>
        <div className="flex items-center p-1 rounded-lg bg-white/[0.03] border border-white/[0.06]">
          <button
            onClick={() => setProto("all")}
            className={cn(
              "px-3 h-8 rounded-md text-[12px] font-medium transition-all",
              proto === "all" ? "bg-white/[0.09] text-white" : "text-[#94A3B8] hover:text-[#CBD5E1]"
            )}
          >
            All protocols
          </button>
          {protocols.map((p) => (
            <button
              key={p}
              onClick={() => setProto(p)}
              className={cn(
                "px-3 h-8 rounded-md text-[12px] font-medium transition-all",
                proto === p ? "bg-white/[0.09] text-white" : "text-[#94A3B8] hover:text-[#CBD5E1]"
              )}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      <Card>
        {!gotData ? (
          <EmptyState mode="offline" />
        ) : filtered.length === 0 ? (
          <EmptyState
            mode="empty"
            icon={flows.length > 0 ? Search : Waves}
            title={flows.length > 0 ? "No flows match the filter" : "No active flows"}
            hint={
              flows.length > 0
                ? "Clear the search box or protocol filter to see all flows."
                : "Flows appear here as the engine reconstructs tuples from live or replayed unidirectional traffic."
            }
          />
        ) : (
          <div className="flex flex-col">
            <div className="grid grid-cols-[110px_1fr_120px_110px_1fr_150px] gap-3 px-4 py-2.5 border-b border-white/[0.06] text-[10px] uppercase tracking-[0.12em] text-[#475569]">
              <span>Flow</span>
              <span>Source → Destination</span>
              <span className="text-right">Packets · Bytes</span>
              <span className="text-center">TCP flags</span>
              <span>Periodicity</span>
              <span className="text-right">Age</span>
            </div>
            {filtered.map((f) => (
              <Row key={f.flow_id} flow={f} />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function Row({ flow }: { flow: FlowRow }) {
  return (
    <div
      className="grid grid-cols-[110px_1fr_120px_110px_1fr_150px] gap-3 items-center px-4 min-h-[46px] border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors"
      title={`Flow ${flow.flow_id}`}
    >
      <span className="flex items-center gap-2 font-mono text-[11px] text-[#64748B] truncate" title={flow.flow_id}>
        <span className="w-1.5 h-1.5 rounded-full bg-[#38BDF8]/70 shrink-0" />
        {flow.flow_id.slice(0, 8)}
      </span>
      <FlowPair
        src={flow.src_ip}
        dst={flow.dst_ip}
        srcPort={flow.src_port}
        dstPort={flow.dst_port}
        protocol={flow.protocol}
        className="min-w-0 truncate"
      />
      <span className="flex items-baseline justify-end gap-2 text-right">
        <span className="text-[12px] font-semibold text-white tabular-nums">{formatNumber(flow.packet_count)}</span>
        <span className="text-[10.5px] text-[#64748B] tabular-nums">{formatBytes(flow.byte_count)}</span>
      </span>
      <span className="flex items-center justify-center gap-1">
        <FlagChip label="SYN" count={flow.syn_count} />
        <FlagChip label="RST" count={flow.rst_count} />
        <FlagChip label="FIN" count={flow.fin_count} />
      </span>
      <span className="flex items-center gap-2">
        <PeriodicityBar value={flow.periodicity} />
      </span>
      <span className="flex items-center justify-end gap-2 text-right">
        <ArrowDownUp size={12} strokeWidth={2} className="text-[#334155] shrink-0 hidden sm:block" />
        <span className="text-[11px] text-[#64748B] tabular-nums whitespace-nowrap">
          {age(flow.age_sec)}
        </span>
      </span>
    </div>
  );
}

function age(sec: number): string {
  if (sec < 60) return `${Math.max(0, Math.round(sec))}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${(sec / 3600).toFixed(1)}h`;
}