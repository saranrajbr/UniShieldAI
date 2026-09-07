import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { api, formatNumber, timeAgo, type Alert } from "../lib/api";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { SeverityBadge } from "../components/alerts/SeverityBadge";
import { ThreatBadge } from "../components/alerts/ThreatBadge";
import { EmptyState } from "../components/alerts/EmptyState";
import { severityMeta, threatMeta } from "../lib/threats";
import { cn } from "../lib/cn";

function Bar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <span className="w-[140px] text-[11px] text-[#94A3B8] text-right truncate" title={label}>
        {label}
      </span>
      <div className="flex-1 h-2.5 rounded-full bg-white/[0.06] overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${Math.max(3, pct)}%`, background: color }} />
      </div>
      <span className="w-14 text-right text-[11px] font-semibold tabular-nums text-[#CBD5E1]">
        {(value * 100).toFixed(1)}%
      </span>
    </div>
  );
}

const FEATURE_LABELS: Record<string, string> = {
  packet_count: "Packet count",
  byte_count: "Total bytes",
  syn_ratio: "SYN ratio",
  unique_dst_ports: "Unique destination ports",
  connection_frequency: "Connection frequency",
  source_entropy: "Source entropy",
  tls_ja3s: "JA3S (TLS client)",
  tls_ja3: "JA3S (TLS)",
  flow_duration: "Flow duration",
  avg_packet_size: "Avg packet size",
  pps: "Packets per second",
  bps: "Bits per second",
  udp_amp_ratio: "UDP amplification ratio",
  flags: "TCP flags summary",
  src_ip: "Source IP",
  dst_ip: "Destination IP",
  src_port: "Source port",
  dst_port: "Destination port",
  protocol: "Protocol",
  threat_type: "Threat type",
  severity: "Severity",
};

export default function Investigation() {
  const { id } = useParams<{ id: string }>();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const res = await api.alert(id);
        if (!cancelled) {
          setAlert(res);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  const evidence = alert?.evidence ?? ({} as Record<string, unknown>);
  const features = (evidence.features ?? {}) as Record<string, unknown>;
  const breakdown = (evidence.score_breakdown ?? {}) as Record<string, unknown>;
  const meta = (evidence.meta ?? {}) as Record<string, unknown>;
  const metaMax = Math.max(...Object.values(breakdown).map(Number), 0.01);
  const tm = threatMeta(alert?.threat_type);

  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title={alert ? tm.label : "Threat investigation"}
        subtitle={
          alert
            ? `${severityMeta(alert.severity).label} severity · risk ${Math.round(alert.risk_score * 100)}% · confidence ${Math.round(alert.confidence * 100)}% · ${tm.blurb}`
            : "Live evidence evidence collector"
        }
        actions={
          <Link
            to="/alerts"
            className="flex items-center gap-1.5 px-3 h-9 rounded-lg bg-white/[0.04] border border-white/[0.08] text-[12px] font-medium text-[#94A3B8] hover:text-white hover:border-white/[0.16] transition-colors"
          >
            <ArrowLeft size={14} strokeWidth={2} /> Back to alerts
          </Link>
        }
      />

      {loading ? (
        <div className="flex flex-col gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}>
              <div className="h-8 w-48 rounded bg-white/[0.05] animate-pulse mb-3" />
              <div className="h-16 rounded bg-white/[0.04] animate-pulse" />
            </Card>
          ))}
        </div>
      ) : error ? (
        <EmptyState
          mode="offline"
          title="Could not load alert"
          hint={`Backend response: ${error}. Check the alert_id and try again.`}
        />
      ) : alert ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Left column: threat + evidence */}
          <div className="flex flex-col gap-4 lg:col-span-2">
            {/* Threat card */}
            <Card>
              <div className="flex flex-col md:flex-row md:items-start gap-5">
                <div
                  className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
                  style={{ background: severityMeta(alert.severity).bg, color: severityMeta(alert.severity).color }}
                >
                  <ShieldAlert size={26} strokeWidth={1.5} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <SeverityBadge severity={alert.severity} />
                    <ThreatBadge type={alert.threat_type} />
                  </div>
                  <h2 className="text-[17px] font-semibold text-white mb-1">{tm.label}</h2>
                  <p className="text-[12px] text-[#94A3B8] leading-relaxed max-w-lg mb-3">
                    {tm.blurb}
                  </p>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-[11px] uppercase tracking-[0.1em] text-[#64748B]">
                    <div>
                      <span className="block text-[16px] font-semibold text-white tabular-nums lowercase tracking-normal">
                        {timeAgo(alert.timestamp)}
                      </span>
                      Detected
                    </div>
                    <div>
                      <span className="block text-[16px] font-semibold text-[#FF9F43] tabular-nums lowercase tracking-normal">
                        {Math.round(alert.risk_score * 100)}%
                      </span>
                      Risk score
                    </div>
                    <div>
                      <span className="block text-[16px] font-semibold text-[#38BDF8] tabular-nums lowercase tracking-normal">
                        {Math.round(alert.confidence * 100)}%
                      </span>
                      Confidence
                    </div>
                    <div>
                      <span className="block text-[13px] font-semibold text-[#CBD5E1] lowercase tracking-normal flex flex-wrap gap-1">
                        {(alert.detection_sources ?? []).map((s) => (
                          <span
                            key={s}
                            className="inline-flex px-2 h-5 rounded-md bg-white/[0.05] border border-white/[0.08] text-[10px] font-medium text-[#A78BFA]"
                          >
                            {s.replace(/_/g, " ")}
                          </span>
                        ))}
                      </span>
                      Detection sources
                    </div>
                  </div>
                </div>
              </div>
            </Card>

            {/* Evidence: features */}
            <Card title="Key features" subtitle="Extracted from the contributing flows">
              {Object.keys(features).length === 0 ? (
                <p className="text-[12px] text-[#64748B]">No feature snapshot recorded with this alert.</p>
              ) : (
                <div className="flex flex-col gap-2.5">
                  {Object.entries(features).map(([k, v]) => (
                    <div key={k} className="flex items-center gap-4">
                      <span className="w-[160px] text-[12px] text-[#94A3B8] text-right truncate" title={FEATURE_LABELS[k] ?? k}>
                        {FEATURE_LABELS[k] ?? k}
                      </span>
                      <span className="flex-1 flex items-center gap-2">
                        {typeof v === "number" && v <= 1 ? (
                          <Bar label="" value={v} max={1} color={severityMeta(alert.severity).bar} />
                        ) : null}
                        <span className="text-[12px] font-semibold text-white tabular-nums">
                          {typeof v === "number" ? (v < 1 && v > 0 ? v.toFixed(4) : formatNumber(v)) : String(v ?? "—")}
                        </span>
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {/* Score breakdown */}
            {Object.keys(breakdown).length > 0 && (
              <Card title="Detection score breakdown" subtitle="Contribution of each detection source to the final fused score">
                <div className="flex flex-col gap-3">
                  {Object.entries(breakdown)
                    .sort(([, a], [, b]) => Number(b) - Number(a))
                    .map(([src, val]) => (
                      <Bar
                        key={src}
                        label={src.replace(/_/g, " ")}
                        value={Number(val)}
                        max={metaMax * 1.1}
                        color={
                          src.includes("ml") || src.includes("anomaly")
                            ? "#FF9F43"
                            : src.includes("rule")
                              ? "#7C5CFC"
                              : "#38BDF8"
                        }
                      />
                    ))}
                </div>
              </Card>
            )}
          </div>

          {/* Right column: context + advisory */}
          <div className="flex flex-col gap-4">
            <Card title="Request details">
              <div className="flex flex-col gap-2.5 text-[12px]">
                <DetailRow label="Alert ID" value={alert.alert_id} mono />
                <DetailRow label="Protocol" value={alert.protocol ?? "—"} />
                <DetailRow label="Source" value={alert.src_ip} mono />
                <DetailRow label="Destination" value={alert.dst_ip} mono />
                <DetailRow
                  label="Detection sources"
                  value={(alert.detection_sources ?? []).map((s) => s.replace(/_/g, " ")).join(", ") || "—"}
                />
              </div>
            </Card>

            <Card title="Additional evidence" subtitle="Any extra meta carried by the alert">
              {Object.keys(meta).length === 0 ? (
                <p className="text-[12px] text-[#64748B]">No additional context recorded.</p>
              ) : (
                <div className="flex flex-col gap-2.5 text-[12px]">
                  {Object.entries(meta).map(([k, v]) => (
                    <DetailRow
                      key={k}
                      label={FEATURE_LABELS[k] ?? k.replace(/_/g, " ")}
                      value={typeof v === "object" ? JSON.stringify(v) : String(v ?? "—")}
                      mono
                    />
                  ))}
                </div>
              )}
            </Card>

            <Card title="Recommended actions (advisory only)">
              <div className="flex flex-col gap-2.5">
                {recommendations(alert.threat_type).map((r, i) => (
                  <div key={i} className="flex gap-2.5 text-[12px] text-[#94A3B8] leading-relaxed">
                    <span style={{ color: severityMeta(alert.severity).color }}>•</span>
                    {r}
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-[#64748B] mt-4 border-t border-white/[0.06] pt-3">
                UniShield AI is a <span className="font-semibold text-[#CBD5E1]">read-only analyzer</span>. This console never blocks or isolates hosts.
                Act on the recommended actions in your actual network infrastructure or SOC console.
              </p>
            </Card>

            <Link
              to="/alerts"
              className="flex items-center justify-center gap-2 h-10 rounded-lg bg-white/[0.04] border border-white/[0.08] text-[12px] font-medium text-[#94A3B8] hover:text-white hover:border-white/[0.16] transition-colors"
            >
              <ArrowLeft size={14} strokeWidth={2} /> Return to alert queue
            </Link>
          </div>
        </div>
      ) : (
        <EmptyState title="Alert not found" hint="This alert_id does not exist in the current engine window." />
      )}
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-3">
      <span className="w-[110px] text-[11px] text-[#64748B] uppercase tracking-wider shrink-0 pt-0.5">
        {label}
      </span>
      <span
        className={cn(
          "text-[12px] font-medium text-[#CBD5E1] break-all",
          mono && "font-mono"
        )}
      >
        {value}
      </span>
    </div>
  );
}

function recommendations(threatType: string): string[] {
  const map: Record<string, string[]> = {
    ddos: ["Confirm if the volume spike is legitimate traffic or an attack pattern.", "Rate-limit inbound from the offending source(s) upstream of this path.", "Verify whether amplification sources are on-path or reflected off public resolvers."],
    dos: ["Check if the target is degraded and correlate with uptime monitoring.", "Add temporary capacity or rate limits until the flood subsides.", "Document the flow tuple and forwarding path for post-incident review."],
    dns_tunneling: ["Check for unexpected DNS query sizes or high TTL values from the source.", "Correlate with the endpoint to determine if the application legitimately uses DNS channels.", "Notify the threat-hunt team if the domain is newly registered or low-reputation."],
    c2_communication: ["Isolate the host for forensic triage (network policy, not via this console).", "Pull host telemetry: scheduled tasks, unusual listening ports, outbound patterns.", "Register the C2 IP/domain in your block list via your infrastructure tooling."],
    port_scan: ["Verify whether the scan originated from an internal recon tool or attacker.", "Correlate with user activity or vulnerability scan schedules.", "Temporarily restrict inbound access to the targeted host from the scanner source."],
    data_exfiltration: ["Validate whether the egress is expected (backup job, software update) and window.", "Rate-limit or quarantine until confirmation from the asset owner.", "Preserve the flow evidence for legal or IR follow-up."],
    suspicious_traffic: ["Review surrounding flows to confirm the pattern is not a legitimate burst.", "Correlate the source with threat intel feeds and internal ownership data.", "Escalate to the SOC if the signature matches an active incident."],
    malware_communication: ["Quarantine the endpoint and pull host logs immediately.", "Confirm with EDR whether the payload matches a known signature.", "Escalate as a confirmed malicious communication incident."],
  };
  return map[threatType] ?? [
    "Treat this detection as a live finding until you have corroborating context.",
    "Verify the source, destination, and path against known-good baselines.",
    "Escalate to the SOC or threat-hunt team if the pattern persists after triage.",
  ];
}