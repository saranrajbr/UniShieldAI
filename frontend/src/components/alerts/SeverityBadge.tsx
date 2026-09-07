import { cn } from "../../lib/cn";
import { severityMeta } from "../../lib/threats";

export function SeverityBadge({
  severity,
  className,
}: {
  severity?: string | null;
  className?: string;
}) {
  const meta = severityMeta(severity);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2.5 h-6 rounded-full text-[11px] font-semibold tracking-wide",
        className
      )}
      style={{ color: meta.color, background: meta.bg, border: `1px solid ${meta.color}33` }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full shrink-0"
        style={{ background: meta.color }}
      />
      {meta.label}
    </span>
  );
}