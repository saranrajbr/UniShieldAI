import type { ReactNode } from "react";
import { RefreshCw } from "lucide-react";
import { cn } from "../../lib/cn";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  showTimeRange?: boolean;
  onRefresh?: () => void;
}

const ranges = ["Last 24 Hours", "Last 7 Days", "Last 30 Days"];

export function PageHeader({
  title,
  subtitle,
  actions,
  showTimeRange = false,
  onRefresh,
}: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="text-[22px] font-semibold text-white tracking-tight">
          {title}
        </h1>
        {subtitle && (
          <p className="text-[13px] text-[#94A3B8] mt-1">{subtitle}</p>
        )}
      </div>
      <div className="flex items-center gap-4">
        {actions}
        {showTimeRange && (
          <>
            <div className="flex items-center p-1 rounded-full bg-white/[0.03] border border-white/[0.06]">
              {ranges.map((r, i) => (
                <button
                  key={r}
                  className={cn(
                    "px-3 h-8 rounded-full text-[12px] font-medium whitespace-nowrap transition-all duration-150",
                    i === 0
                      ? "bg-white/[0.08] text-white"
                      : "text-[#94A3B8] hover:text-[#CBD5E1]"
                  )}
                >
                  {r}
                </button>
              ))}
            </div>
            <button
              onClick={onRefresh}
              className="w-9 h-9 rounded-lg bg-white/[0.03] border border-white/[0.06] flex items-center justify-center text-[#94A3B8] hover:text-[#CBD5E1] hover:border-white/[0.12] transition-colors"
            >
              <RefreshCw size={16} strokeWidth={1.75} />
            </button>
          </>
        )}
      </div>
    </div>
  );
}
