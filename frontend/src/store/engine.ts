import { create } from "zustand";
import {
  api,
  type Alert,
  type DetectionEngines,
  type EngineMetrics,
  type FlowRow,
  type ModelsResponse,
  type RulesResponse,
  type RuntimeMetrics,
  type TrafficMetrics,
  type TrafficStats,
} from "../lib/api";

const MAX_ALERTS = 200;
const MAX_HISTORY = 24; // 24 samples x 5s  ≈ 2 min rolling trend (was 5 min)
const ACTIVE_WINDOW_MS = 20000; // a source is ACTIVE while traffic is seen within 20s
const STOPPED_PRUNE_MS = 10 * 60 * 1000; // drop ended sources after 10 min
const MAX_TOASTS = 5;

/** Alert IDs we have already surfaced — polling baselines never re-toast. */
const seenIds = new Set<string>();
let toastSeq = 0;

export type ToastKind = "alert";

export interface Toast {
  id: number;
  kind: ToastKind;
  title: string;
  desc: string;
  severity: string;
  alertId?: string;
  createdAt: number;
}

export interface SourceActivity {
  ip: string;
  proto: string;
  dst: string;
  threat: string;
  severity: string;
  firstSeen: number;
  lastSeen: number;
  active: boolean;
  endedAt: number | null;
  alertCount: number;
}

interface EngineState {
  alerts: Alert[];
  stats: TrafficStats | null;
  metrics: RuntimeMetrics | null;
  trafficMetrics: TrafficMetrics | null;
  engine: EngineMetrics | null;
  flows: FlowRow[];
  engines: DetectionEngines | null;
  models: ModelsResponse | null;
  rules: RulesResponse | null;

  wsConnected: boolean;
  loading: boolean;
  error: string | null;
  gotData: boolean;
  lastUpdated: number | null;
  history: Array<{ t: string; flows: number; packets: number; alerts: number }>;

  /* live attack tracking + popups */
  sources: SourceActivity[];
  toasts: Toast[];

  refreshAll: () => Promise<void>;
  refreshAlerts: () => Promise<void>;
  resolveAlert: (alertId: string) => Promise<void>;
  pushAlert: (alert: Alert, via?: "ws" | "poll") => void;
  absorbAlerts: (list: Alert[]) => void;
  touchFlows: (flows: FlowRow[]) => void;
  pushMetricsSample: (m: RuntimeMetrics, packetsPerSec?: number) => void;
  tick: () => void;
  dismissToast: (id: number) => void;
  setWsConnected: (v: boolean) => void;
  setError: (e: string | null) => void;
}

const pushHistory = (
  s: EngineState,
  time: number,
  flows: number,
  packets: number,
  alerts: number
) => {
  const t = new Date(time).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  return [...s.history, { t, flows, packets, alerts }].slice(-MAX_HISTORY);
};

function bumpSource(
  list: SourceActivity[],
  ip: string,
  fields: Partial<Pick<SourceActivity, "proto" | "dst" | "threat" | "severity">>,
  ts: number
): SourceActivity[] {
  const idx = list.findIndex((x) => x.ip === ip);
  if (idx < 0) {
    return [
      {
        ip,
        proto: fields.proto ?? "",
        dst: fields.dst ?? "",
        threat: fields.threat ?? "",
        severity: fields.severity ?? "info",
        firstSeen: ts,
        lastSeen: ts,
        active: true,
        endedAt: null,
        alertCount: 0,
      },
      ...list,
    ];
  }
  const cur = list[idx];
  if (cur.lastSeen === ts) return list;
  const next: SourceActivity = {
    ...cur,
    proto: fields.proto ?? cur.proto,
    dst: fields.dst ?? cur.dst,
    threat: fields.threat ?? cur.threat,
    severity: fields.severity ?? cur.severity,
    lastSeen: ts,
    active: true,
    endedAt: null,
    alertCount:
      fields.threat && cur.threat !== fields.threat ? cur.alertCount + 1 : cur.alertCount,
  };
  const copy = list.slice();
  copy[idx] = next;
  return copy;
}

function sourcesFromAlertsAndFlows(
  prev: SourceActivity[],
  alerts: Alert[],
  flows: FlowRow[]
): SourceActivity[] {
  let sources = prev;
  const now = Date.now();
  for (const a of alerts) {
    sources = bumpSource(sources, a.src_ip, {
      proto: a.protocol ?? undefined,
      dst: a.dst_ip,
      threat: a.threat_type,
      severity: a.severity,
    }, now);
  }
  for (const f of flows) {
    sources = bumpSource(sources, f.src_ip, { proto: f.protocol, dst: f.dst_ip }, now);
  }
  return sources;
}

function makeAlertToast(alert: Alert): Toast {
  return {
    id: ++toastSeq,
    kind: "alert",
    title: "Threat detected",
    desc: `${alert.threat_type} · ${alert.src_ip} → ${alert.dst_ip}`,
    severity: alert.severity,
    alertId: alert.alert_id,
    createdAt: Date.now(),
  };
}

export const useEngine = create<EngineState>((set, get) => ({
  alerts: [],
  stats: null,
  metrics: null,
  trafficMetrics: null,
  engine: null,
  flows: [],
  engines: null,
  models: null,
  rules: null,

  wsConnected: false,
  loading: false,
  error: null,
  gotData: false,
  lastUpdated: null,
  history: [],

  sources: [],
  toasts: [],

  refreshAll: async () => {
    const setLoading = !get().metrics;
    if (setLoading) set({ loading: true });
    try {
      const [alerts, stats, metrics, trafficMetrics, engine, flows] =
        await Promise.allSettled([
          api.alerts(),
          api.trafficStats(),
          api.metrics(),
          api.trafficMetrics(),
          api.engineMetrics(),
          api.flows(),
        ]);
      const results = [alerts, stats, metrics, trafficMetrics, engine, flows];
      const ok = results.filter((r) => r.status === "fulfilled").length;
      const base = get();
      const patch: Partial<EngineState> = {
        lastUpdated: Date.now(),
        loading: false,
        gotData: base.gotData || ok > 0,
        error: ok === 0 ? "Backend engine unreachable" : null,
      };
      if (alerts.status === "fulfilled") {
        const list = alerts.value.alerts;
        list.forEach((a) => a.alert_id && seenIds.add(a.alert_id));
        patch.alerts = list.slice(0, MAX_ALERTS);
      }
      if (stats.status === "fulfilled") patch.stats = stats.value;
      if (metrics.status === "fulfilled") {
        patch.metrics = metrics.value;
        patch.history = pushHistory(
          base,
          Date.now(),
          metrics.value.flow_rate_fps,
          trafficMetrics.status === "fulfilled"
            ? trafficMetrics.value.packets_per_sec
            : 0,
          metrics.value.alerts_raised
        );
      }
      if (trafficMetrics.status === "fulfilled")
        patch.trafficMetrics = trafficMetrics.value;
      if (engine.status === "fulfilled") patch.engine = engine.value;
      if (flows.status === "fulfilled") patch.flows = flows.value.flows;
      patch.sources = sourcesFromAlertsAndFlows(
        base.sources,
        patch.alerts ?? base.alerts,
        patch.flows ?? base.flows
      );
      set(patch);
    } catch (err) {
      set({
        loading: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  },

  refreshAlerts: async () => {
    try {
      const resp = await api.alerts();
      const list = resp.alerts;
      list.forEach((a) => a.alert_id && seenIds.add(a.alert_id));
      set((s) => ({
        alerts: list.slice(0, MAX_ALERTS),
        sources: sourcesFromAlertsAndFlows(s.sources, list, s.flows),
        error: null,
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : String(err) });
    }
  },

  resolveAlert: async (alertId: string) => {
    try {
      const resp = await api.resolveAlert(alertId);
      set((s) => ({
        alerts: s.alerts.map((a) =>
          a.alert_id === alertId ? { ...a, status: resp.status } : a
        ),
      }));
    } catch (err) {
      set({ error: err instanceof Error ? err.message : String(err) });
    }
  },

  pushAlert: (alert, via = "ws") => {
    const key = alert.alert_id;
    const isNew = !seenIds.has(key);
    if (isNew && key) seenIds.add(key);
    set((s) => {
      const alerts = isNew
        ? [alert, ...s.alerts.filter((a) => a.alert_id !== key)].slice(0, MAX_ALERTS)
        : s.alerts;
      const sources = bumpSource(s.sources, alert.src_ip, {
        proto: alert.protocol ?? undefined,
        dst: alert.dst_ip,
        threat: alert.threat_type,
        severity: alert.severity,
      }, Date.now());
      const patch: Partial<EngineState> = { alerts, sources };
      if (isNew && via === "ws") {
        patch.toasts = [...s.toasts, makeAlertToast(alert)].slice(-MAX_TOASTS);
      }
      return patch;
    });
  },

  absorbAlerts: (list) => {
    list.forEach((a) => a.alert_id && seenIds.add(a.alert_id));
    set((s) => ({
      alerts: list.slice(0, MAX_ALERTS),
      sources: sourcesFromAlertsAndFlows(s.sources, list, s.flows),
    }));
  },

  touchFlows: (flows) =>
    set((s) => ({
      sources: sourcesFromAlertsAndFlows(s.sources, s.alerts, flows),
    })),

  pushMetricsSample: (m, packetsPerSec = 0) =>
    set((s) => ({
      metrics: m,
      lastUpdated: Date.now(),
      history: pushHistory(s, Date.now(), m.flow_rate_fps, packetsPerSec, m.alerts_raised),
    })),

  tick: () =>
    set((s) => {
      const now = Date.now();
      const sources = s.sources
        .map((src) => {
          if (src.active && now - src.lastSeen > ACTIVE_WINDOW_MS) {
            return { ...src, active: false, endedAt: now };
          }
          return src;
        })
        .filter(
          (src) => src.active || src.endedAt === null || now - src.lastSeen < STOPPED_PRUNE_MS
        );
      if (sources.length === s.sources.length && sources.every((v, i) => v === s.sources[i])) return {};
      return { sources };
    }),

  dismissToast: (id) =>
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  setWsConnected: (v) => set({ wsConnected: v }),
  setError: (e) => set({ error: e }),
}));