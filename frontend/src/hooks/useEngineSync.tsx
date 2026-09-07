import { useEffect, useRef } from "react";
import { useEngine } from "../store/engine";
import type { Alert, EngineMetrics, RuntimeMetrics } from "../lib/api";

const POLL_MS = 5000;

export function useEngineSync() {
  const refreshAll = useEngine((s) => s.refreshAll);
  const pushAlert = useEngine((s) => s.pushAlert);
  const setWsConnected = useEngine((s) => s.setWsConnected);
  const setError = useEngine((s) => s.setError);

  const handlers = useRef({ refreshAll, pushAlert, setWsConnected, setError });
  handlers.current = { refreshAll, pushAlert, setWsConnected, setError };

  useEffect(() => {
    const h = handlers.current;
    let disposed = false;

    h.refreshAll();
    const poll = window.setInterval(() => {
      if (!disposed) h.refreshAll();
    }, POLL_MS);

    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    let ws: WebSocket | null = null;
    let retry = 0;
    let closed = false;

    const connect = () => {
      if (closed) return;
      ws = new WebSocket(`${proto}//${location.host}/ws`);
      const t = window.setTimeout(() => {
        if (ws && ws.readyState === WebSocket.CONNECTING) ws.close();
      }, 4000);

      ws.onopen = () => {
        h.setWsConnected(true);
        retry = 0;
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(String(ev.data));
          if (msg && typeof msg === "object") {
            if (msg.alert_id) {
              h.pushAlert(msg as Alert);
            } else if (msg.type === "metrics") {
              const m = msg.data as RuntimeMetrics;
              if (typeof m?.flow_rate_fps === "number") {
                useEngine.setState({
                  metrics: m,
                  lastUpdated: Date.now(),
                });
              }
            } else if (msg.type === "engine_state") {
              useEngine.setState({ engine: msg.data as EngineMetrics });
            }
          }
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        clearTimeout(t);
        h.setWsConnected(false);
        const delay = Math.min(15000, 1000 * 2 ** retry);
        retry += 1;
        if (!closed) window.setTimeout(connect, delay);
      };
      ws.onerror = () => {
        if (ws) ws.close();
      };
    };
    connect();

    return () => {
      closed = true;
      disposed = true;
      window.clearInterval(poll);
      if (ws) ws.close();
    };
  }, []);
}

/** App-level inline connection badge (guard component keeps hooks in-tree). */
export function ConnectionBadge() {
  const wsConnected = useEngine((s) => s.wsConnected);
  const error = useEngine((s) => s.error);
  const lastUpdated = useEngine((s) => s.lastUpdated);

  return (
    <span
      className={`flex items-center gap-1.5 text-[11px] px-2.5 h-7 rounded-full border font-medium ${
        wsConnected
          ? "text-[#34D399] border-[#34D399]/30 bg-[#34D399]/10"
          : "text-[#FF9F43] border-[#FF9F43]/30 bg-[#FF9F43]/10"
      }`}
      title={error ? `Engine sync issue: ${error}` : "Live UniShield AI engine feed"}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          wsConnected ? "bg-[#34D399] live-source" : "bg-[#FF9F43]"
        }`}
      />
      {wsConnected ? "LIVE" : lastUpdated ? "POLLING" : "OFFLINE"}
      <span className="hidden lg:inline text-[10px] opacity-70">
        {lastUpdated
          ? new Date(lastUpdated).toLocaleTimeString("en-US", {
              hour12: false,
              hour: "2-digit",
              minute: "2-digit",
            })
          : ""}
      </span>
    </span>
  );
}