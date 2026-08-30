const PALETTE: ReadonlyArray<{ fg: string; bg: string }> = [
  { fg: "#7CD4D4", bg: "rgba(84,179,179,0.18)" }, // teal
  { fg: "#93BDF5", bg: "rgba(26,98,166,0.30)" }, // blue
  { fg: "#F5A29B", bg: "rgba(212,32,39,0.22)" }, // red
  { fg: "#CDB2F7", bg: "rgba(142,51,255,0.24)" }, // purple
  { fg: "#8FE0AC", bg: "rgba(34,197,94,0.20)" }, // green
  { fg: "#F2C98A", bg: "rgba(255,171,0,0.20)" }, // amber
];

function hashIndex(name: string): number {
  let hash = 0;
  for (const ch of name) {
    hash = (hash * 31 + (ch.codePointAt(0) ?? 0)) % 997;
  }
  return hash % PALETTE.length;
}

export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) {
    const letters = parts[0].match(/[A-Za-z0-9]/g) ?? [...parts[0]];
    return (letters.slice(0, 2).join("") || parts[0].slice(0, 2) || "?").toUpperCase();
  }
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

const SIZES = {
  xs: "size-8 text-[10px]",
  sm: "size-9 text-xs",
  md: "size-11 text-sm",
  lg: "size-14 text-lg",
  xl: "size-16 text-xl",
} as const;

/** Colored initials circle, deterministic per name (like the prototype). */
export function Initials({
  name,
  size = "md",
  className = "",
}: {
  name: string;
  size?: keyof typeof SIZES;
  className?: string;
}) {
  const palette = PALETTE[hashIndex(name || "?")];
  return (
    <span
      aria-hidden="true"
      className={`inline-flex flex-none select-none items-center justify-center rounded-full font-extrabold ${SIZES[size]} ${className}`}
      style={{ color: palette.fg, backgroundColor: palette.bg }}
    >
      {initialsOf(name || "?")}
    </span>
  );
}
