"use client";

import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Icon } from "@/components/icon";

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: number;
  kind: ToastKind;
  message: string;
}

type PushToast = (message: string, kind?: ToastKind) => void;

const ToastContext = createContext<PushToast>(() => {});

/** `const toast = useToast(); toast("Saved.", "success");` */
export function useToast(): PushToast {
  return useContext(ToastContext);
}

const KIND_STYLES: Record<ToastKind, string> = {
  success: "border-[#22C55E]/30 bg-[#0C2E22]/95 text-[#8FE0AC]",
  error: "border-[#FF5630]/35 bg-[#33120C]/95 text-[#FF9C86]",
  info: "border-white/15 bg-[#0B2B2B]/95 text-white/85",
};

const KIND_ICONS: Record<ToastKind, "check-circle" | "alert" | "info"> = {
  success: "check-circle",
  error: "alert",
  info: "info",
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const push = useCallback<PushToast>((message, kind = "info") => {
    const id = nextId.current;
    nextId.current += 1;
    setItems((prev) => [...prev, { id, kind, message }]);
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex flex-col items-center gap-2 px-4"
      >
        {items.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`pointer-events-auto flex max-w-md items-start gap-2.5 rounded-lg border px-4 py-3 text-sm shadow-xl backdrop-blur ${KIND_STYLES[t.kind]}`}
          >
            <Icon
              name={KIND_ICONS[t.kind]}
              className="mt-0.5 size-4 flex-none"
            />
            <span>{t.message}</span>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
