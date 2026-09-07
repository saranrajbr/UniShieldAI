import { cn } from "../../lib/cn";
import { threatMeta } from "../../lib/threats";

export function ThreatBadge({
  type,
  className,
}: {
  type?: string | null;
  className?: string;
}) {
  const meta = threatMeta(type);
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 h-6 rounded-md bg-white/[0.04] border border-white/[0.08] text-[11px] font-medium text-[#CBD5E1]",
        className
      )}
      title={meta.blurb}
    >
      {meta.label}
    </span>
  );
}