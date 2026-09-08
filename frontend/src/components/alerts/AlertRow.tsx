import { Link } from "react-router-dom";
import { ArrowRight, Circle } from "lucide-react";
import type { Alert } from "../../lib/api";
import { SeverityBadge } from "./SeverityBadge";
import { threatMeta } from "../../lib/threats";
import { timeAgo } from "../../lib/api";
import { cn } from "../../lib/cn";

export function FlowPair({
  src,
  dst,
  srcPort,
  dstPort,
  protocol,
  className,
}: {
  src: string;
  dst: string;
  srcPort?: number | null;
  dstPort?: number | null;
  protocol?: string | null;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-2 font-mono text-[12px]", className)}>
      <span className="text-[#94A3B8]">
        {src}
        {srcPort != null ? `:${srcPort}` : ""}
      </span>
      <ArrowRight size={11} strokeWidth={2} className="text-[#475569]" />
      <span className="text-[#E2E8F0]">
        {dst}
        {dstPort != null ? `:${dstPort}` : ""}
      </span>
      {protocol && (
        <span className="ml-1 px-1.5 h-[18px] rounded text-[10px] font-bold bg-[#7C5CFC]/15 text-[#A78BFA] flex items-center">
          {protocol}
        </span>
      )}
    </span>
  );
}

export function AlertRow({
  alert,
  dense,
}: {
  alert: Alert;
  dense?: boolean;
}) {
  const meta = threatMeta(alert.threat_type);
  const conf = typeof alert.confidence === "number" ? Math.round(alert.confidence * 100) : null;
  return (
    <Link
      to={`/investigation/${alert.alert_id}`}
      className={cn(
        "flex items-center gap-3 px-4 hover:bg-white/[0.03] transition-colors border-b border-white/[0.04] group",
        dense ? "h-12" : "min-h-[52px] py-2"
      )}
    >
      <span className="flex items-center justify-center w-2 shrink-0">
        <Circle size={8} fill="currentColor" className="text-white/[0.25]" />
      </span>
      <SeverityBadge severity={alert.severity} className="w-[84px] justify-center shrink-0" />
      <span className={cn("flex flex-col justify-center min-w-0 flex-1", dense && "max-w-[190px]")}>
        <span className={cn("text-[12.5px] font-medium text-white truncate", dense && "text-[12px]")}>
          {meta.label}
        </span>
        <span className="text-[10.5px] text-[#64748B] truncate hidden md:block">
          {meta.blurb}
        </span>
      </span>
      <FlowPair
        src={alert.src_ip}
        dst={alert.dst_ip}
        srcPort={alert.src_port}
        dstPort={alert.dst_port}
        protocol={alert.protocol}
        className="hidden xl:inline-flex min-w-0 truncate"
      />
      {conf != null && (
        <span
          className={cn(
            "hidden sm:inline-flex px-2 h-5 rounded tabular-nums text-[10.5px] font-semibold shrink-0",
            conf >= 80
              ? "bg-[#FF4D6A]/10 text-[#FF8CA0]"
              : conf >= 50
                ? "bg-[#FF9F43]/10 text-[#FFC48A]"
                : "bg-white/[0.05] text-[#94A3B8]"
          )}
        >
          {conf}% conf
        </span>
      )}
      <span className="text-[11px] text-[#64748B] tabular-nums whitespace-nowrap shrink-0 w-[92px] text-right">
        {timeAgo(alert.timestamp)}
      </span>
    </Link>
  );
}