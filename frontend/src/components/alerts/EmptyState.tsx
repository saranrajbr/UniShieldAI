import type { LucideIcon } from "lucide-react";
import { Satellite, SearchX, WifiOff } from "lucide-react";

export function EmptyState({
  mode,
  title,
  hint,
  icon: Icon,
}: {
  mode?: "empty" | "offline";
  title?: string;
  hint?: string;
  icon?: LucideIcon;
}) {
  const Cmp = Icon ?? (mode === "offline" ? WifiOff : Satellite);
  return (
    <div className="flex flex-col items-center justify-center py-14 px-6 text-center">
      <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-[#64748B] mb-3">
        <Cmp size={22} strokeWidth={1.5} />
      </div>
      <p className="text-[13px] font-medium text-[#94A3B8]">
        {title ?? (mode === "offline" ? "Backend not reachable" : "Waiting for data")}
      </p>
      <p className="text-[11px] text-[#475569] mt-1 max-w-[320px]">
        {hint ??
          (mode === "offline"
            ? "Start the backend engine and make sure it is listening on :8000."
            : "Live data appears here as soon as the engine processes traffic.")}
      </p>
    </div>
  );
}

export function SearchEmptyState({ query }: { query: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 px-6 text-center">
      <div className="w-12 h-12 rounded-2xl bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-[#64748B] mb-3">
        <SearchX size={20} strokeWidth={1.5} />
      </div>
      <p className="text-[13px] font-medium text-[#94A3B8]">
        No alerts match “{query}”
      </p>
      <p className="text-[11px] text-[#475569] mt-1">
        Try a different search term or clear the filters.
      </p>
    </div>
  );
}