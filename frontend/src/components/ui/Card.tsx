import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

interface CardProps {
  children: ReactNode;
  className?: string;
  title?: ReactNode;
  subtitle?: ReactNode;
  action?: ReactNode;
  headerClassName?: string;
}

export function Card({
  children,
  className,
  title,
  subtitle,
  action,
  headerClassName,
}: CardProps) {
  return (
    <div className={cn("glass-panel glass-hover", className)}>
      {(title || action) && (
        <div
          className={cn(
            "flex items-center justify-between gap-4 border-b border-white/[0.06] px-5 py-4",
            headerClassName
          )}
        >
          <div>
            {title && (
              <h3 className="text-[15px] font-semibold text-white leading-tight">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-[11px] text-[#64748B] mt-0.5">{subtitle}</p>
            )}
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}
