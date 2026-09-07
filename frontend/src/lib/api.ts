const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText} ${path}`);
  }
  return (await res.json()) as T;
}

/* ----------------------------- schemas ----------------------------- */

export interface Alert {
  id: string;
  alert_id: string;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  threat_type: string;
  severity: string;
  confidence: number;
  risk_score: number;
  evidence?: Record<string, unknown> | null;
  detection_sources?: string[];
  status?: string;
}

export interface AlertListResponse {
  total: number;
  alerts: Alert[];
}

export interface TrafficStats {
  flows_queued: number;
  active_flows: number;
  connections: number;
  processed: number;
  window: string;
}

export interface FlowRow {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  packet_count: number;
  byte_count: number;
  syn_count: number;
  ack_count: number;
  rst_count: number;
  fin_count: number;
  first_seen: number;
  last_seen: number;
  age_sec: number;
  periodicity: number;
}

export interface FlowsResponse {
  count: number;
  limit: number;
  window: string;
  flows: FlowRow[];
}

export interface RuntimeMetrics {
  uptime_sec: number;
  flows_processed: number;
  alerts_raised: number;
  rules_fired: number;
  ml_inferences: number;
  flow_rate_fps: number;
  cpu_percent: number;
  memory_mb: number;
  queue_high_watermark: number;
  processing_errors: number;
}

export interface TrafficMetrics {
  packets_per_sec: number;
  bytes_per_sec: number;
  flows_per_sec: number;
  connections_per_sec: number;
}

export interface FlowExportStats {
  udp_host: string;
  udp_port: number;
  datagrams_received: number;
  records_parsed: number;
  records_rejected: number;
}

export interface EngineMetrics {
  flows_queued: number;
  active_flows: number;
  alerts_recent: number;
  alert_stats?: Record<string, number>;
  ml_stats?: Record<string, unknown>;
  rules?: Record<string, number>;
  flow_export?: FlowExportStats;
}

export interface DetectionEngines {
  rules: { loaded: number; categories: Record<string, number> };
  ml: Record<string, unknown>;
  decision: { threshold: number | null; is_threat_gt: number };
}

export interface ModelsResponse {
  status: Record<string, unknown>;
  paths: Record<string, string>;
}

export interface RulesResponse {
  count: number;
  rules: Array<Record<string, unknown>>;
}

/* ------------------------------ client ----------------------------- */

export const api = {
  /* alerts */
  alerts: (limit = 100) =>
    request<AlertListResponse>(`/api/v1/alerts?limit=${limit}`),
  liveAlerts: (limit = 100) =>
    request<AlertListResponse>(`/api/v1/alerts/live?limit=${limit}`),
  alert: (alertId: string) =>
    request<Alert>(`/api/v1/alerts/${encodeURIComponent(alertId)}`),
  resolveAlert: (alertId: string) =>
    request<{ ok: boolean; status: string; alert_id: string }>(
      `/api/v1/alerts/${encodeURIComponent(alertId)}/resolve`,
      { method: "POST" }
    ),

  /* traffic */
  trafficStats: () => request<TrafficStats>(`/api/v1/traffic/stats`),
  flows: (limit = 200) =>
    request<FlowsResponse>(`/api/v1/traffic/flows?limit=${limit}`),

  /* metrics */
  metrics: () => request<RuntimeMetrics>(`/api/v1/metrics`),
  trafficMetrics: () => request<TrafficMetrics>(`/api/v1/metrics/traffic`),
  engineMetrics: () => request<EngineMetrics>(`/api/v1/metrics/engine`),

  /* engine */
  detectionEngines: () => request<DetectionEngines>(`/api/v1/detection/engines`),
  models: () => request<ModelsResponse>(`/api/v1/models`),
  rules: () => request<RulesResponse>(`/api/v1/models/rules`),
};

/* ---------------------------- helpers ----------------------------- */

export function humanThreatType(t: string): string {
  const map: Record<string, string> = {
    ddos: "Distributed DoS",
    dos: "Denial of Service",
    dns_tunneling: "DNS Tunneling",
    c2_communication: "C2 Beaconing",
    port_scan: "Port Scan",
    data_exfiltration: "Data Exfiltration",
    reconnaissance: "Reconnaissance",
    suspicious_traffic: "Suspicious Traffic",
    malware_communication: "Malware Communication",
    malicious_ips: "Malicious Communication",
    brute_force: "Brute Force",
    lateral_movement: "Lateral Movement",
    benign: "Benign",
  };
  if (map[t]) return map[t];
  return t.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());
}

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log2(bytes) / 10));
  return `${(bytes / 2 ** (10 * i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined) return "0";
  return n.toLocaleString("en-US");
}

export function formatTs(ts: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function timeAgo(ts: string): string {
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s} sec ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  return `${h} hr ago`;
}