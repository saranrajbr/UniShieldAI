import { NavLink } from "react-router-dom";
import {
  LayoutGrid,
  ShieldAlert,
  Activity,
  Cpu,
  Info,
  ChevronsLeft,
} from "lucide-react";
import { cn } from "../../lib/cn";
import { Logo } from "../brand/Logo";
import { useEngine } from "../../store/engine";

const navItems = [
  { label: "Security Overview", path: "/", icon: LayoutGrid },
  { label: "Alerts", path: "/alerts", icon: ShieldAlert, badge: true },
  { label: "Live Traffic", path: "/traffic", icon: Activity },
  { label: "Detection Engine", path: "/engine", icon: Cpu },
  { label: "About · PS", path: "/about", icon: Info },
];

function AlertBadge() {
  const alerts = useEngine((s) => s.alerts);
  const open = alerts.filter(
    (a) => a.status !== "resolved" && a.status !== "ignored"
  ).length;
  if (open === 0) return null;
  const critical = alerts.some((a) => a.severity === "critical");
  return (
    <span
      className={cn(
        "hidden md:inline-flex items-center h-5 min-w-5 px-1.5 rounded-full text-[10px] font-bold ml-auto",
        critical
          ? "bg-[#FF4D6A]/20 text-[#FF8CA0] border border-[#FF4D6A]/40"
          : "bg-white/[0.08] text-[#94A3B8] border border-white/[0.1]"
      )}
      title={`${open} open alerts`}
    >
      {open}
    </span>
  );
}

function Tooltip({ label }: { label: string }) {
  return (
    <span role="tooltip" className="hidden md:block absolute left-full top-1/2 -translate-y-1/2 ml-3 px-2.5 py-1 rounded-lg bg-[#161D2F] border border-white/[0.08] text-[12px] font-medium text-[#CBD5E1] whitespace-nowrap opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity duration-150 z-50 shadow-xl">
      {label}
    </span>
  );
}

function NavLinkButton({
  label,
  path,
  icon: Icon,
  end,
  expanded,
  index,
  badge,
}: {
  label: string;
  path: string;
  icon: typeof LayoutGrid;
  end?: boolean;
  expanded: boolean;
  index?: number;
  badge?: boolean;
}) {
  return (
    <div className="relative group flex justify-center md:justify-start md:w-full">
      <NavLink
        to={path}
        end={end ?? path === "/"}
        className={({ isActive }) =>
          cn(
            "relative flex items-center h-11 rounded-xl justify-center transition-all duration-300 ease-in-out",
            expanded
              ? "md:w-full md:justify-start md:px-3"
              : "md:w-16 md:px-0",
            isActive
              ? "accent-gradient glow-violet text-white"
              : "text-[#64748B] hover:text-[#CBD5E1] hover:bg-white/[0.05]"
          )
        }
      >
        {({ isActive }) => (
          <>
            {isActive && (
              <span className="absolute top-0 md:top-1/2 right-1/2 translate-x-1/2 md:translate-x-0 md:right-auto md:left-0 md:-translate-y-1/2 w-6 md:w-[3px] h-[3px] md:h-6 rounded-full md:rounded-r bg-white/80 md:bg-[#A78BFA]" />
            )}
            <Icon size={20} strokeWidth={1.75} className="shrink-0" />
            <span
              style={{ transitionDelay: expanded ? `${(index ?? 0) * 45}ms` : "0ms" }}
              className={cn(
                "hidden md:inline-block overflow-hidden whitespace-nowrap text-[12.5px] font-medium transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]",
                expanded
                  ? "opacity-100 translate-x-0 max-w-[200px] ml-3"
                  : "opacity-0 -translate-x-2 max-w-0 ml-0"
              )}
            >
              {label}
            </span>
            {badge && <AlertBadge />}
          </>
        )}
      </NavLink>
      {!expanded && <Tooltip label={label} />}
    </div>
  );
}

export function Sidebar({
  expanded,
  onToggle,
}: {
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <aside
      className={cn(
        "fixed z-40 bottom-0 inset-x-0 h-14 md:h-full md:inset-y-0 md:left-0 md:flex md:flex-col md:py-4 bg-[#0B0B17]/95 md:bg-[#0B0B17] backdrop-blur-xl border-t md:border-t-0 md:border-r border-white/[0.06] transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)]",
        expanded ? "md:w-60" : "md:w-16"
      )}
    >
      {/* Logo (desktop only) */}
      <div
        className={cn(
          "hidden md:flex items-center mb-2 shrink-0 transition-all duration-300 ease-in-out",
          expanded ? "justify-start px-1" : "justify-center"
        )}
      >
        <Logo withWordmark={expanded} />
      </div>
      <p
        className={cn(
          "hidden md:flex items-center gap-1.5 px-2 pb-4 text-[10px] uppercase tracking-[0.14em] text-[#475569] transition-opacity",
          !expanded && "opacity-0"
        )}
      >
        Network SOC <span>·</span> Read-only
      </p>

      {/* Primary nav — row on mobile, column on desktop */}
      <nav className="flex md:flex-col md:flex-1 gap-1.5 w-full items-center justify-around md:justify-start">
        {navItems.map((item, i) => (
          <NavLinkButton key={item.path} {...item} expanded={expanded} index={i} />
        ))}
      </nav>

      {/* Folders footer: collapse toggle (desktop only) */}
      <div className="hidden md:flex flex-col gap-1.5 border-t border-white/[0.06] pt-3 shrink-0">
        <button
          type="button"
          aria-label={expanded ? "Collapse sidebar" : "Expand sidebar"}
          aria-expanded={expanded}
          onClick={onToggle}
          className={cn(
            "relative flex items-center h-11 rounded-xl justify-center transition-all duration-300 ease-in-out text-[#64748B] hover:text-[#CBD5E1] hover:bg-white/[0.05] mt-1",
            expanded ? "md:w-full md:justify-start md:px-3" : "md:w-16 md:px-0"
          )}
        >
          <ChevronsLeft
            size={20}
            strokeWidth={1.75}
            className={cn(
              "shrink-0 transition-transform duration-500 ease-[cubic-bezier(0.16,1,0.3,1)]",
              expanded ? "" : "rotate-180"
            )}
          />
          <span
            style={{ transitionDelay: expanded ? "90ms" : "0ms" }}
            className={cn(
              "hidden md:inline-block overflow-hidden whitespace-nowrap text-[12.5px] font-medium transition-all duration-300 ease-[cubic-bezier(0.16,1,0.3,1)]",
              expanded
                ? "opacity-100 translate-x-0 max-w-[200px] ml-3"
                : "opacity-0 -translate-x-2 max-w-0 ml-0"
            )}
          >
            Collapse
          </span>
        </button>
      </div>
    </aside>
  );
}