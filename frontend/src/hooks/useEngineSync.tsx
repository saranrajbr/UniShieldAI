import { useEffect, useRef } from "react";
import { useEngine } from "../store/engine";
import type { Alert, EngineMetrics, RuntimeMetrics } from "../lib/api";

const POLL_MS = 5000;
const TICK_MS = 2000;

export function useEngineSync() {
  const refreshAll = useEngine((s) => s.refreshAll);
  const pushAlert = useEngine((s) => s.pushAlert);
  const pushMetricsSample = useEngine((s) => s.pushMetricsSample);
  const tick = useEngine((s) => s.tick);
  const setWsConnected = useEngine((s) => s.setWsConnected);
  const setError = useEngine((s) => s.setError);

  const handlers = useRef({ refreshAll, pushAlert, pushMetricsSample, tick, setWsConnected, setError });
  handlers.current = { refreshAll, pushAlert, pushMetricsSample, tick, setWsConnected, setError };

  useEffect(() => {
    const h = handlers.current;
    let disposed = false;

    h.refreshAll();
    const poll = window.setInterval(() => {
      if (!disposed) h.refreshAll();
    }, POLL_MS);
    const ticker = window.setInterval(() => {
      if (!disposed) h.tick();
    }, TICK_MS);

    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const sockets: WebSocket[] = [];

    const connect = (url: string, onMsg: (msg: unknown) => void, onOpen: () => void) => {
      const ws = new WebSocket(url);
      sockets.push(ws);
      let retry = 0;
      const failTimeout = window.setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) ws.close();
      }, 4000);
      ws.onopen = () => {
        window.clearTimeout(failTimeout);
        onOpen();
        retry = 0;
      };
      ws.onmessage = (ev) => {
        try {
          onMsg(JSON.parse(String(ev.data)));
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        window.clearTimeout(failTimeout);
        if (disposed || ws.readyState !== WebSocket.CLOSED) return;
        const delay = Math.min(15000, 1000 * 2 ** retry);
        retry += 1;
        window.setTimeout(() => {
          if (!disposed) connect(url, onMsg, onOpen);
        }, delay);
      };
      ws.onerror = () => ws.close();
    };

    // Channel 1: /ws — system metrics + engine state envelopes.
    connect(
      `${proto}//${location.host}/ws`,
      (msg) => {
        const m = msg as { type?: string; data?: RuntimeMetrics };
        if (m?.type === "metrics" && typeof m.data?.flow_rate_fps === "number") {
          h.pushMetricsSample(m.data, 0);
        } else if (m?.type === "engine_state") {
          useEngine.setState({ engine: m.data as unknown as EngineMetrics });
        }
      },
      () => h.setWsConnected(true)
    );

    // Channel 2: /ws/alerts — bare alert payloads broadcast on new detections.
    connect(
      `${proto}//${location.host}/ws/alerts`,
      (msg) => {
        const a = msg as Alert;
        if (a && typeof a === "object" && a.alert_id) {
          h.pushAlert(a, "ws");
        }
      },
      () => undefined
    );

    return () => {
      disposed = true;
      window.clearInterval(poll);
      window.clearInterval(ticker);
      sockets.forEach((ws) => ws.close());
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