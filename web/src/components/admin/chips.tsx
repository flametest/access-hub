"use client";

/** Admin-specific chips: effect (allow/deny), resource type, org role. */
export function EffectChip({
  effect,
  className = "",
}: {
  effect: string;
  className?: string;
}) {
  const key = (effect || "").toLowerCase();
  const isDeny = key === "deny";
  return (
    <span
      className={`inline-flex flex-none items-center whitespace-nowrap rounded-md border px-2.5 py-0.5 text-xs font-semibold ${className} ${
        isDeny
          ? "border-[#FF5630]/30 bg-[#FF5630]/15 text-[#FF9C86]"
          : "border-[#22C55E]/30 bg-[#22C55E]/15 text-[#7CE49F]"
      }`}
    >
      {isDeny ? "Deny" : "Allow"}
    </span>
  );
}

const TYPE_TONES: Record<string, string> = {
  menu: "border-ah-accent/30 bg-ah-accent/15 text-[#7CD4D4]",
  api: "border-[#93BDF5]/30 bg-[#93BDF5]/15 text-[#B7D2F8]",
  button: "border-[#CDB2F7]/30 bg-[#CDB2F7]/15 text-[#DCC9FA]",
};

/** Resource type chip: menu / api / button (design.md §2.3 single table). */
export function ResourceTypeChip({
  type,
  className = "",
}: {
  type: string;
  className?: string;
}) {
  const key = (type || "").toLowerCase();
  return (
    <span
      className={`inline-flex flex-none items-center whitespace-nowrap rounded-md border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide ${className} ${
        TYPE_TONES[key] ?? "border-white/15 bg-white/[0.07] text-white/60"
      }`}
    >
      {key || "unknown"}
    </span>
  );
}
