import { humanThreatType } from "./api";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface SeverityMeta {
  label: string;
  color: string;
  bg: string;
  bar: string;
}

export const SEVERITY: Record<Severity, SeverityMeta> = {
  critical: { label: "Critical", color: "#FF4D6A", bg: "rgba(255,77,106,0.12)", bar: "#FF4D6A" },
  high: { label: "High", color: "#FF9F43", bg: "rgba(255,159,67,0.12)", bar: "#FF9F43" },
  medium: { label: "Medium", color: "#FFD93D", bg: "rgba(255,217,61,0.12)", bar: "#FFD93D" },
  low: { label: "Low", color: "#6BCB77", bg: "rgba(107,203,119,0.12)", bar: "#6BCB77" },
  info: { label: "Info", color: "#7C86A3", bg: "rgba(124,134,163,0.12)", bar: "#7C86A3" },
};

export function severityMeta(s?: string | null): SeverityMeta {
  return SEVERITY[(s as Severity) || "info"] ?? SEVERITY.info;
}

export interface ThreatMeta {
  type: string;
  label: string;
  blurb: string;
}

export const THREATS: ThreatMeta[] = [
  { type: "ddos", label: "Distributed DoS", blurb: "Amplified or volumetric flooding that exhausts target capacity." },
  { type: "dos", label: "Denial of Service", blurb: "Single-source flood consuming service capacity." },
  { type: "dns_tunneling", label: "DNS Tunneling", blurb: "Outbound DNS channel carrying covert data." },
  { type: "c2_communication", label: "C2 Beaconing", blurb: "Regular contact with a command-and-control server." },
  { type: "port_scan", label: "Port Scan", blurb: "Sequential probing of many ports on a target." },
  { type: "data_exfiltration", label: "Data Exfiltration", blurb: "Sustained outbound transfer of sensitive data." },
  { type: "reconnaissance", label: "Reconnaissance", blurb: "Low-volume probing to map hosts and services." },
  { type: "malware_communication", label: "Malware Communication", blurb: "Traffic matching a known-malicious fingerprint." },
  { type: "malicious_ips", label: "Malicious Communication", blurb: "Contact with a known-malicious destination." },
  { type: "brute_force", label: "Brute Force", blurb: "Failed repeated authentication attempts at volume." },
  { type: "lateral_movement", label: "Lateral Movement", blurb: "Internal pivoting between hosts." },
  { type: "suspicious_traffic", label: "Suspicious Traffic", blurb: "Anomalous pattern not matching normal baselines." },
  { type: "benign", label: "Benign", blurb: "Normal traffic, no known threat signal." },
];

export function threatMeta(t?: string | null): ThreatMeta {
  return THREATS.find((x) => x.type === t) ?? {
    type: t ?? "unknown",
    label: t ? humanThreatType(t) : "Unknown",
    blurb: "Unclassified detection — review evidence for context.",
  };
}