import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 className="text-[22px] font-semibold text-white tracking-tight">
          {title}
        </h1>
        {subtitle && (
          <p className="text-[13px] text-[#94A3B8] mt-1">{subtitle}</p>
        )}
      </div>
      {actions && (
        <div className="flex items-center gap-4 shrink-0">{actions}</div>
      )}
    </div>
  );
}
