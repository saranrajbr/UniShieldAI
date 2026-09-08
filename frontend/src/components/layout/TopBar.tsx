import type { ReactNode } from "react";
import { ShieldCheck, RefreshCw, Radio, ShieldAlert } from "lucide-react";
import { cn } from "../../lib/cn";
import { useEngine } from "../../store/engine";
import { formatNumber } from "../../lib/api";

function LiveStat({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent: string;
}) {
  return (
    <div
      className="hidden lg:flex flex-col leading-tight px-3 py-1 border-l border-white/[0.06]"
      style={{ color: accent }}
    >
      <span className="text-[13px] font-semibold tabular-nums">{value}</span>
      <span className="text-[10px] uppercase tracking-wider opacity-60">
        {label}
      </span>
    </div>
  );
}

export function TopBar({ expanded, badge }: { expanded: boolean; badge?: ReactNode }) {
  const metrics = useEngine((s) => s.metrics);
  const stats = useEngine((s) => s.stats);
  const alerts = useEngine((s) => s.alerts);
  const refreshAll = useEngine((s) => s.refreshAll);
  const gotData = useEngine((s) => s.gotData);

  const open = alerts.filter(
    (a) => a.status !== "resolved" && a.status !== "ignored"
  ).length;
  const critical = alerts.filter((a) => a.severity === "critical").length;

  return (
    <header
      className={cn(
        "fixed top-0 left-0 right-0 z-30 h-16 px-4 md:px-6 bg-[#0A0A14]/80 backdrop-blur-md border-b border-white/[0.06] flex items-center justify-between gap-3 transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] md:left-16",
        expanded && "md:left-[15rem]"
      )}
    >
      {/* Product identity */}
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="w-8 h-8 rounded-lg accent-gradient glow-violet flex items-center justify-center text-white shrink-0">
          <ShieldCheck size={16} strokeWidth={2} />
        </div>
        <div className="leading-tight min-w-0">
          <p className="text-[13px] font-semibold text-white truncate">
            UniShield AI
          </p>
          <p className="text-[10.5px] text-[#64748B] truncate">
            Unidirectional Traffic Defense · PS 26145
          </p>
        </div>
      </div>

      <div className="hidden md:flex items-center">
        <div
          className={cn(
            "hidden 2xl:flex items-center gap-1 text-[11px] px-2.5 h-7 rounded-full border font-medium",
            gotData
              ? "text-[#6BCB77] border-[#6BCB77]/25 bg-[#6BCB77]/5"
              : "text-[#94A3B8] border-white/[0.08] bg-white/[0.03]"
          )}
        >
          <Radio size={12} strokeWidth={2} />
          Ingest
        </div>
      </div>

      {/* Live counters */}
      <div className="flex items-center gap-1">
        <LiveStat
          label="Flow rate"
          value={metrics ? `${formatNumber(metrics.flow_rate_fps)}/s` : "—"}
          accent="#7C86A3"
        />
        <LiveStat
          label="Active flows"
          value={stats ? `${stats.active_flows}` : "—"}
          accent="#7C86A3"
        />
        <LiveStat
          label="Alerts raised"
          value={metrics ? `${formatNumber(metrics.alerts_raised)}` : "—"}
          accent="#7C86A3"
        />
        <div
          className={cn(
            "flex items-center gap-1.5 pl-3 ml-1",
            critical > 0 ? "text-[#FF4D6A]" : "text-[#6BCB77]"
          )}
          title={critical > 0 ? `${critical} critical alerts open` : "No critical alerts"}
        >
          <ShieldAlert size={15} strokeWidth={1.75} />
          <span className="text-[12px] font-semibold tabular-nums">
            {open} open
          </span>
        </div>
      </div>

      <div className="flex-1" />

      {/* Right side: refresh + live badge */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          aria-label="Refresh now"
          onClick={() => refreshAll()}
          className="w-9 h-9 rounded-lg bg-white/[0.03] border border-white/[0.06] flex items-center justify-center text-[#94A3B8] hover:text-[#CBD5E1] hover:border-white/[0.12] transition-colors"
        >
          <RefreshCw size={16} strokeWidth={1.75} />
        </button>
        {badge}
      </div>
    </header>
  );
}