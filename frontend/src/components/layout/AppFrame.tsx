import { useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { ToastStack } from "../ui/ToastStack";
import { cn } from "../../lib/cn";
import { useEngineSync, ConnectionBadge } from "../../hooks/useEngineSync";
import { useEngine } from "../../store/engine";
import { WifiOff, RefreshCw } from "lucide-react";

function ConnectivityBanner() {
  const error = useEngine((s) => s.error);
  const gotData = useEngine((s) => s.gotData);
  const refreshAll = useEngine((s) => s.refreshAll);
  if (!error) return null;
  return (
    <div
      className="absolute top-16 inset-x-0 z-20 flex items-center gap-3 px-5 h-9 bg-[#3A2B10]/90 border-b border-[#FF9F43]/30 text-[12px] text-[#FFD9A0]"
      role="alert"
    >
      <WifiOff size={14} strokeWidth={2} />
      <span className="truncate">
        {gotData
          ? "Backend sync lost — showing last received data, reconnecting…"
          : "Backend engine not reachable — waiting for connection…"}
      </span>
      <button
        type="button"
        onClick={() => refreshAll()}
        className="ml-auto flex items-center gap-1.5 px-2.5 h-6 rounded-md bg-white/[0.06] hover:bg-white/[0.12] text-[#FFD9A0] transition-colors"
      >
        <RefreshCw size={12} strokeWidth={2} /> Retry
      </button>
    </div>
  );
}

export function AppFrame() {
  const [expanded, setExpanded] = useState(false);
  useEngineSync();

  return (
    <div className="h-full bg-[#0A0A14] text-white overflow-hidden">
      <Sidebar expanded={expanded} onToggle={() => setExpanded((v) => !v)} />
      <TopBar expanded={expanded} badge={<ConnectionBadge />} />
      <ConnectivityBanner />
      <ToastStack />
      <main
        className={cn(
          "absolute top-16 bottom-14 left-0 right-0 md:bottom-0 overflow-y-auto thin-scroll transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)]",
          expanded ? "md:left-[15rem]" : "md:left-16"
        )}
      >
        <div className="min-h-full ambient">
          <Outlet />
        </div>
      </main>
    </div>
  );
}