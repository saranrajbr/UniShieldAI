import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "../../lib/cn";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "md";
  children: ReactNode;
}

const variants = {
  primary:
    "accent-gradient hover:bg-none hover:brightness-110 text-white shadow-[0_2px_16px_rgba(124,92,252,0.4)] hover:shadow-[0_2px_24px_rgba(124,92,252,0.55)] border border-white/10",
  secondary:
    "bg-white/[0.04] hover:bg-white/[0.08] text-[#CBD5E1] border border-white/[0.06]",
  ghost: "bg-transparent hover:bg-white/[0.04] text-[#94A3B8] border border-transparent",
};

const sizes = {
  sm: "h-8 px-3 text-[12px]",
  md: "h-10 px-4 text-[13px]",
};

export function Button({
  variant = "primary",
  size = "md",
  className,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed select-none",
        variants[variant],
        sizes[size],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}
