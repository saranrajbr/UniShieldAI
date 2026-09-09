import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { FileSearch, RefreshCw, ChevronRight } from "lucide-react";
import { PageHeader } from "../components/layout/PageHeader";
import { Card } from "../components/ui/Card";
import { EmptyState } from "../components/alerts/EmptyState";
import { cn } from "../lib/cn";
import {
  api,
  type ActiveCapture,
  type CaptureFile,
  type CapturePacket,
  type CapturePacketsResponse,
} from "../lib/api";

type View = "active" | "incidents";

export default function PacketInspector() {
  const [searchParams] = useSearchParams();
  const initialFile = searchParams.get("file");
  const initialView: View = searchParams.get("view") === "incidents" ? "incidents" : "active";
  const [view, setView] = useState<View>(initialView);
  const [active, setActive] = useState<ActiveCapture | null>(null);
  const [incidents, setIncidents] = useState<CaptureFile[]>([]);
  const [file, setFile] = useState<string>(initialFile ?? "active/current.pcap");
  const [limit, setLimit] = useState(200);
  const [data, setData] = useState<CapturePacketsResponse | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshFiles = useCallback(async () => {
    try {
      const [a, i] = await Promise.all([api.activeCapture(), api.captures()]);
      setActive(a);
      setIncidents(i.files);
    } catch {
      /* backend offline — keep previous state */
    }
  }, []);

  useEffect(() => {
    refreshFiles();
    const t = window.setInterval(refreshFiles, 15000);
    return () => window.clearInterval(t);
  }, [refreshFiles]);

  const loadPackets = useCallback(
    async (target: string) => {
      setBusy(true);
      setError(null);
      try {
        const res = await api.capturePackets(target, limit);
        setData(res);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load packets");
        setData(null);
      } finally {
        setBusy(false);
        setSelected(null);
      }
    },
    [limit]
  );

  useEffect(() => {
    loadPackets(file);
  }, [file, loadPackets]);

  const pickFile = (name: string) => {
    setFile(name);
  };

  const packet = selected != null ? data?.packets[selected] : null;

  return (
    <div className="p-5 md:p-6 max-w-[1400px] mx-auto">
      <PageHeader
        title="Packet Inspector"
        subtitle="Wireshark-style view of captured evidence — select packets to inspect the frame decode"
        actions={
          <button
            type="button"
            onClick={() => {
              loadPackets(file);
            }}
            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-lg text-[12px] font-medium text-[#CBD5E1] bg-white/[0.05] border border-white/[0.08] hover:bg-white/[0.1] transition-colors"
          >
            <RefreshCw size={13} className={cn(busy && "animate-spin")} />
            Refresh
          </button>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Capture source picker */}
        <Card
          title="Capture source"
          subtitle="Active live buffer or archived incident evidence"
          className="lg:col-span-1 self-start"
        >
          <div className="flex flex-col gap-4">
            <div className="flex gap-1 rounded-lg p-0.5 bg-white/[0.04] border border-white/[0.07]">
              {(["active", "incidents"] as View[]).map((v) => (
                <button
                  key={v}
                  type="button"
                  onClick={() => setView(v)}
                  className={cn(
                    "flex-1 h-8 rounded-md text-[11.5px] font-semibold uppercase tracking-wider transition-colors",
                    view === v
                      ? "accent-gradient glow-violet text-white"
                      : "text-[#64748B] hover:text-[#CBD5E1]"
                  )}
                >
                  {v === "active" ? "Live buffer" : "Incidents"}
                </button>
              ))}
            </div>

            {view === "active" ? (
              <button
                type="button"
                onClick={() => pickFile("active/current.pcap")}
                className={cn(
                  "flex items-center gap-3 rounded-xl border p-3 text-left transition-colors",
                  file === "active/current.pcap"
                    ? "border-[#A78BFA]/40 bg-[#A78BFA]/[0.06]"
                    : "border-white/[0.07] hover:border-white/[0.14]"
                )}
              >
                <span className="w-2 h-2 rounded-full bg-[#6BCB77] live-source shrink-0" />
                <span className="min-w-0">
                  <span className="block text-[12.5px] font-semibold text-[#CBD5E1]">
                    current.pcap
                  </span>
                  <span className="block text-[11px] text-[#64748B] tabular-nums">
                    {active?.exists
                      ? `${fmtBytes(active.size)} · ${new Date((active.mtime ?? 0) * 1000).toLocaleTimeString()}`
                      : "not writing yet"}
                  </span>
                </span>
                <span className="ml-auto text-[10px] uppercase tracking-wider text-[#6BCB77]">
                  live
                </span>
              </button>
            ) : (
              <div className="flex flex-col gap-1.5 max-h-[420px] overflow-y-auto pr-1">
                {incidents.length === 0 ? (
                  <p className="text-[12px] text-[#64748B] py-3 text-center">
                    No preserved incident captures yet.
                  </p>
                ) : (
                  incidents.map((f) => {
                    const isSel = file === f.path.replace(/^captures\//, "");
                    return (
                      <button
                        key={f.path}
                        type="button"
                        onClick={() => pickFile(f.path.replace(/^captures\//, ""))}
                        className={cn(
                          "flex items-center gap-2 rounded-lg border px-2.5 py-2 text-left transition-colors",
                          isSel
                            ? "border-[#A78BFA]/40 bg-[#A78BFA]/[0.06]"
                            : "border-white/[0.06] hover:border-white/[0.12]"
                        )}
                      >
                        <FileSearch size={14} className="shrink-0 text-[#64748B]" />
                        <span className="min-w-0">
                          <span className="block text-[11.5px] font-medium text-[#CBD5E1] truncate font-mono">
                            {f.name}
                          </span>
                          <span className="block text-[10.5px] text-[#64748B] tabular-nums">
                            {fmtBytes(f.size)}
                          </span>
                        </span>
                      </button>
                    );
                  })
                )}
              </div>
            )}

            <div className="flex items-center justify-between pt-1 border-t border-white/[0.06]">
              <label className="text-[11.5px] text-[#64748B]">
                Rows{" "}
                <select
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                  className="ml-1 bg-[#12141F] border border-white/[0.1] rounded-md text-[11.5px] px-1.5 py-0.5 text-[#CBD5E1]"
                >
                  {[100, 200, 500, 1000].map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              </label>
              <span className="text-[11px] text-[#64748B] tabular-nums">
                {data ? `${data.packets.length}/${data.total}` : "—"}
              </span>
            </div>
          </div>
        </Card>

        {/* Packet list */}
        <Card
          title="Packets"
          subtitle={packet?.summary ?? "Click a packet to inspect its decode"}
          className="lg:col-span-2"
        >
          {error ? (
            <div className="py-8">
              <EmptyState title="Capture unavailable" hint={error} />
            </div>
          ) : !data || data.packets.length === 0 ? (
            <div className="py-8">
              <EmptyState
                title={busy ? "Reading capture…" : "No packets in view"}
                hint="Choose a capture source on the left, or wait for traffic to be recorded."
              />
            </div>
          ) : (
            <div className="overflow-x-auto -mx-5 -mb-5">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="text-[10px] uppercase tracking-[0.12em] text-[#475569]">
                    <th className="px-4 py-2 font-semibold">#</th>
                    <th className="px-2 py-2 font-semibold">Time</th>
                    <th className="px-2 py-2 font-semibold">Source</th>
                    <th className="px-2 py-2 font-semibold">Destination</th>
                    <th className="px-2 py-2 font-semibold">Proto</th>
                    <th className="px-2 py-2 font-semibold">Len</th>
                    <th className="px-2 py-2 font-semibold">Flags</th>
                    <th className="px-2 py-2 font-semibold">Info</th>
                  </tr>
                </thead>
                <tbody>
                  {data.packets.map((p, i) => (
                    <tr
                      key={i}
                      onClick={() => setSelected(selected === i ? null : i)}
                      className={cn(
                        "text-[12px] border-t border-white/[0.04] cursor-pointer hover:bg-white/[0.03] transition-colors",
                        selected === i && "bg-[#A78BFA]/[0.08]"
                      )}
                    >
                      <td className="px-4 py-1.5 text-[#475569] tabular-nums">{i + 1}</td>
                      <td className="px-2 py-1.5 text-[#94A3B8] tabular-nums whitespace-nowrap">
                        {fmtPktTime(p)}
                      </td>
                      <td className="px-2 py-1.5 font-mono text-[#CBD5E1] whitespace-nowrap">{p.src}</td>
                      <td className="px-2 py-1.5 font-mono text-[#CBD5E1] whitespace-nowrap">{p.dst}</td>
                      <td className="px-2 py-1.5">
                        <ProtoPill proto={p.proto} />
                      </td>
                      <td className="px-2 py-1.5 text-[#94A3B8] tabular-nums">{p.len}</td>
                      <td className="px-2 py-1.5 font-mono text-[#64748B]">{p.flags || "·"}</td>
                      <td className="px-2 py-1.5 text-[#64748B] truncate max-w-[220px]">{p.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {/* Selected packet decode — Wireshark-style tree + hex */}
      {packet && (
        <Card title="Frame details" subtitle="Protocol decode + raw bytes" className="mt-4">
          <PacketDecode packet={packet} />
        </Card>
      )}
    </div>
  );
}

function ProtoPill({ proto }: { proto: string }) {
  const color =
    proto === "tcp" ? "text-[#38BDF8] bg-[#38BDF8]/10" :
    proto === "udp" ? "text-[#FFD93D] bg-[#FFD93D]/10" :
    proto === "icmp" ? "text-[#6BCB77] bg-[#6BCB77]/10" :
    "text-[#94A3B8] bg-white/[0.06]";
  return (
    <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider", color)}>
      {proto}
    </span>
  );
}

function fmtPktTime(p: CapturePacket): string {
  if (!p.time) return "—";
  const t = new Date(p.time * 1000);
  const ms = Math.floor((p.time % 1) * 1000);
  return `${t.toLocaleTimeString("en-US", { hour12: false })}.${String(ms).padStart(3, "0")}`;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function PacketDecode({ packet }: { packet: CapturePacket }) {
  const decode = packet.decode;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      {/* Decoded tree */}
      <div className="text-[12px] leading-relaxed">
        <TreeLabel label={`Frame ${packet.len} bytes (Ethernet + IP)`} depth={0} open>
          {decode?.ip && (
            <>
              <TreeLabel label={`Internet Protocol Version ${decode.ip.version}, Src: ${decode.ip.src}, Dst: ${decode.ip.dst}`} depth={1} open>
                <TreeKV k="Version" v={String(decode.ip.version)} depth={2} />
                <TreeKV k="Header length" v={`${decode.ip.header_len_bytes} bytes`} depth={2} />
                <TreeKV k="TOS / DSCP" v={String(decode.ip.tos)} depth={2} />
                <TreeKV k="TTL" v={String(decode.ip.ttl)} depth={2} />
                <TreeKV k="Protocol" v={protoName(decode.ip.protocol)} depth={2} />
              </TreeLabel>
            </>
          )}
          {decode?.tcp && (
            <TreeLabel
              label={`Transmission Control Protocol, Src Port: ${decode.tcp.src_port}, Dst Port: ${decode.tcp.dst_port}`}
              depth={1}
              open
            >
              <TreeKV k="Source Port" v={String(decode.tcp.src_port)} depth={2} />
              <TreeKV k="Destination Port" v={String(decode.tcp.dst_port)} depth={2} />
              <TreeKV k="Sequence" v={String(decode.tcp.seq)} depth={2} />
              <TreeKV k="Acknowledgment" v={String(decode.tcp.ack)} depth={2} />
              <TreeKV k="Flags" v={decode.tcp.flags || "—"} depth={2} />
              <TreeKV k="Window" v={String(decode.tcp.window)} depth={2} />
              {decode.tcp.checksum && <TreeKV k="Checksum" v={decode.tcp.checksum} depth={2} />}
            </TreeLabel>
          )}
          {decode?.udp && (
            <TreeLabel
              label={`User Datagram Protocol, Src Port: ${decode.udp.src_port}, Dst Port: ${decode.udp.dst_port}`}
              depth={1}
              open
            >
              <TreeKV k="Source Port" v={String(decode.udp.src_port)} depth={2} />
              <TreeKV k="Destination Port" v={String(decode.udp.dst_port)} depth={2} />
              <TreeKV k="Length" v={`${decode.udp.length} bytes`} depth={2} />
              {decode.udp.checksum && <TreeKV k="Checksum" v={decode.udp.checksum} depth={2} />}
            </TreeLabel>
          )}
          {decode?.icmp && (
            <TreeLabel label={`Internet Control Message Protocol`} depth={1} open>
              <TreeKV k="Type" v={String(decode.icmp.type)} depth={2} />
              <TreeKV k="Code" v={String(decode.icmp.code)} depth={2} />
              {decode.icmp.checksum && <TreeKV k="Checksum" v={decode.icmp.checksum} depth={2} />}
            </TreeLabel>
          )}
          {decode?.payload_len != null && (
            <TreeLabel label={`Payload (${decode.payload_len} bytes)`} depth={1} open>
              {decode.payload_preview && (
                <TreeKV k="ASCII preview" v={JSON.stringify(decode.payload_preview)} depth={2} />
              )}
            </TreeLabel>
          )}
        </TreeLabel>
      </div>

      {/* Hex dump */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <p className="text-[11px] uppercase tracking-[0.12em] text-[#475569]">
            Raw bytes {packet.hex ? `(${packet.hex.length / 2} B)` : ""}
          </p>
        </div>
        {packet.hex ? (
          <HexDump hex={packet.hex} />
        ) : (
          <p className="text-[12px] text-[#64748B]">No hex payload available.</p>
        )}
      </div>
    </div>
  );
}

function TreeLabel({
  label,
  depth,
  open,
  children,
}: {
  label: string;
  depth: number;
  open?: boolean;
  children?: React.ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(open ?? false);
  return (
    <div>
      <div
        className="flex items-center gap-1.5 cursor-pointer select-none"
        style={{ paddingLeft: depth * 14 }}
        onClick={() => setIsOpen((v) => !v)}
      >
        <ChevronRight
          size={12}
          className={cn("text-[#475569] transition-transform", isOpen && "rotate-90")}
        />
        <span className={cn(depth === 0 ? "text-white font-semibold" : "text-[#CBD5E1]")}>
          {label}
        </span>
      </div>
      {isOpen && children}
    </div>
  );
}

function TreeKV({ k, v, depth }: { k: string; v: string; depth: number }) {
  return (
    <div className="flex items-baseline gap-2" style={{ paddingLeft: depth * 14 + 18 }}>
      <span className="text-[#64748B]">{k}:</span>
      <span className="text-[#38BDF8] font-mono text-[11.5px]">{v}</span>
    </div>
  );
}

function protoName(n: number): string {
  return ["", "icmp", "", "", "", "", "tcp", "", "", "", "", "", "", "", "", "", ""][n] ?? String(n);
}

function HexDump({ hex }: { hex: string }) {
  const rows = useMemo(() => {
    const bytes = hex.match(/.{1,2}/g) ?? [];
    const out: { addr: string; hexStr: string; ascii: string }[] = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const ascii = chunk
        .map((b) => {
          const c = parseInt(b, 16);
          return c >= 32 && c < 127 ? String.fromCharCode(c) : ".";
        })
        .join("");
      out.push({
        addr: (i).toString(16).padStart(4, "0"),
        hexStr: chunk.join(" "),
        ascii,
      });
    }
    return out;
  }, [hex]);

  return (
    <div className="overflow-x-auto rounded-lg border border-white/[0.06] bg-[#0B0B17]">
      <table className="w-full text-left">
        <thead>
          <tr className="text-[10px] text-[#475569] uppercase tracking-wider">
            <th className="px-2 py-1.5 font-semibold">Offset</th>
            <th className="px-2 py-1.5 font-semibold">Bytes</th>
            <th className="px-2 py-1.5 font-semibold">ASCII</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.addr} className="font-mono text-[11.5px] border-t border-white/[0.04]">
              <td className="px-2 py-1 text-[#475569]">{r.addr}</td>
              <td className="px-2 py-1 text-[#CBD5E1] whitespace-nowrap">{r.hexStr}</td>
              <td className="px-2 py-1 text-[#64748B] whitespace-nowrap">{r.ascii}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}