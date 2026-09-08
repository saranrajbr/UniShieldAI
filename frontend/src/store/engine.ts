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
const MAX_HISTORY = 60;

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

  refreshAll: () => Promise<void>;
  refreshAlerts: () => Promise<void>;
  resolveAlert: (alertId: string) => Promise<void>;
  pushAlert: (alert: Alert) => void;
  setWsConnected: (v: boolean) => void;
  setError: (e: string | null) => void;
}

export const useEngine = create<EngineState>((set, get) => {
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
    const history = [
      ...s.history,
      { t, flows, packets, alerts },
    ].slice(-MAX_HISTORY);
    return history;
  };

  return {
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
        if (alerts.status === "fulfilled")
          patch.alerts = alerts.value.alerts.slice(0, MAX_ALERTS);
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
        set({ alerts: resp.alerts.slice(0, MAX_ALERTS), error: null });
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

    pushAlert: (alert) =>
      set((s) => ({
        alerts: [alert, ...s.alerts.filter((a) => a.alert_id !== alert.alert_id)].slice(
          0,
          MAX_ALERTS
        ),
      })),

    setWsConnected: (v) => set({ wsConnected: v }),
    setError: (e) => set({ error: e }),
  };
});