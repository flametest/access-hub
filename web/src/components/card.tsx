import type { HTMLAttributes } from "react";

/**
 * Soft rounded card on the dark teal canvas — rgba-white overlay per the
 * prototype's card style (16px radius, hairline border, soft elevation).
 */
export function Card({
  className = "",
  ...rest
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...rest}
      className={`rounded-2xl border border-white/10 bg-white/[0.06] shadow-[0_12px_24px_-8px_rgba(0,0,0,0.35)] ${className}`}
    />
  );
}
