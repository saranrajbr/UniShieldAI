import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, ArrowRight, X } from "lucide-react";
import { useEngine, type Toast } from "../../store/engine";
import { severityMeta } from "../../lib/threats";
import { cn } from "../../lib/cn";

const TOAST_TTL = 9000;

function ToastCard({
  toast,
  onDismiss,
  onOpen,
}: {
  toast: Toast;
  onDismiss: () => void;
  onOpen: () => void;
}) {
  const [closing, setClosing] = useState(false);
  useEffect(() => {
    const t = window.setTimeout(() => {
      setClosing(true);
      window.setTimeout(onDismiss, 210);
    }, TOAST_TTL);
    return () => window.clearTimeout(t);
  }, [onDismiss]);

  const meta = severityMeta(toast.severity);

  return (
    <div
      role="status"
      className={cn("toast-in", closing && "toast-out")}
      style={{ borderColor: `${meta.color}55` }}
    >
      <div
        className="relative flex gap-3 items-start p-3 pr-10 rounded-xl border bg-[#12141F]/95 backdrop-blur-md shadow-2xl shadow-black/50 overflow-hidden cursor-pointer"
        onClick={onOpen}
      >
        <span
          className="absolute inset-y-0 left-0 w-[3px]"
          style={{ background: meta.color }}
        />
        <span
          className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 live-source"
          style={{ background: meta.bg, color: meta.color }}
        >
          <ShieldAlert size={17} strokeWidth={2} />
        </span>
        <div className="leading-snug min-w-0 flex-1">
          <p className="text-[13px] font-semibold text-white flex items-center gap-2">
            Threat detected
            <span
              className="text-[9px] font-bold uppercase tracking-wider px-1.5 h-[16px] rounded flex items-center live-source"
              style={{ color: meta.color, background: meta.bg }}
            >
              live
            </span>
          </p>
          <p className="text-[11.5px] text-[#CBD5E1] truncate">{toast.desc}</p>
          <p className="text-[10.5px] text-[#64748B] truncate">
            {humanThreat(toast.desc, meta.label)}
          </p>
        </div>
        <span className="hidden sm:flex flex-col items-center gap-1 shrink-0" aria-hidden>
          <span className="text-[9px] uppercase tracking-wider text-[#64748B]">Open</span>
          <ArrowRight size={12} strokeWidth={2} style={{ color: meta.color }} />
        </span>
        <button
          type="button"
          aria-label="Dismiss notification"
          onClick={(e) => {
            e.stopPropagation();
            onDismiss();
          }}
          className="absolute top-2 right-2 w-6 h-6 rounded-md flex items-center justify-center text-[#64748B] hover:text-white hover:bg-white/[0.06] transition-colors"
        >
          <X size={13} strokeWidth={2} />
        </button>
      </div>
    </div>
  );
}

function humanThreat(desc: string, fallback: string): string {
  const type = desc.split("·")[0]?.trim() ?? "";
  if (!type) return fallback;
  return type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function ToastStack() {
  const toasts = useEngine((s) => s.toasts);
  const dismissToast = useEngine((s) => s.dismissToast);
  const navigate = useNavigate();

  return (
    <div
      className="fixed top-[4.6rem] right-4 z-50 flex flex-col gap-2 w-[340px] max-w-[calc(100vw-2rem)] pointer-events-none"
      aria-live="assertive"
    >
      {toasts.map((t) => (
        <div key={t.id} className="pointer-events-auto">
          <ToastCard
            toast={t}
            onDismiss={() => dismissToast(t.id)}
            onOpen={() => t.alertId && navigate(`/investigation/${t.alertId}`)}
          />
        </div>
      ))}
    </div>
  );
}