import type { LucideIcon } from "lucide-react";
import { cn } from "../../lib/cn";

interface StatCardProps {
  label: string;
  value: string;
  icon: LucideIcon;
  delta?: string;
  hint?: string;
  accent?: string;
  className?: string;
  loading?: boolean;
}

export function StatCard({
  label,
  value,
  icon: Icon,
  delta,
  hint,
  accent = "#A78BFA",
  className,
  loading,
}: StatCardProps) {
  return (
    <div className={cn("glass-panel glass-hover p-4", className)}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] uppercase tracking-[0.12em] text-[#64748B] font-medium">
          {label}
        </span>
        <span
          className="w-7 h-7 rounded-lg flex items-center justify-center"
          style={{ background: `${accent}1A`, color: accent }}
        >
          <Icon size={14} strokeWidth={2} />
        </span>
      </div>
      <div className="flex items-baseline gap-2">
        {loading ? (
          <div className="h-6 w-24 rounded bg-white/[0.05] animate-pulse" />
        ) : (
          <span className="text-[22px] font-semibold text-white tabular-nums tracking-tight">
            {value}
          </span>
        )}
        {delta && (
          <span className="text-[11px] font-medium text-[#34D399]">{delta}</span>
        )}
      </div>
      {hint && <p className="text-[11px] text-[#64748B] mt-1">{hint}</p>}
    </div>
  );
}