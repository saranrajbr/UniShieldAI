import { cn } from "../../lib/cn";

interface LogoProps {
  markClassName?: string;
  iconSize?: number;
  withWordmark?: boolean;
  wordmarkClassName?: string;
}

function BrandMark({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 3l7.5 2.8v5.4c0 4.4-3 8-7.5 9.8-4.5-1.8-7.5-5.4-7.5-9.8V5.8L12 3z"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path
        d="M8.4 12l2.4 2.4 4.8-4.8"
        stroke="currentColor"
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Logo({
  markClassName,
  iconSize = 18,
  withWordmark = false,
  wordmarkClassName,
}: LogoProps) {
  return (
    <div className="flex items-center gap-2.5 select-none">
      <div
        className={cn(
          "w-8 h-8 rounded-xl accent-gradient glow-violet flex items-center justify-center text-white shrink-0",
          markClassName
        )}
      >
        <BrandMark size={iconSize} />
      </div>

      {withWordmark && (
        <span className={cn("flex items-baseline", wordmarkClassName)}>
            <span className="text-[15px] font-bold tracking-wide bg-gradient-to-r from-[#A78BFA] to-[#C4B5FD] bg-clip-text text-transparent">
              UNISHIELD
            </span>
            <span className="text-[15px] font-bold tracking-wide text-[#64748B]">
              {" "}AI
            </span>
          </span>
      )}
    </div>
  );
}