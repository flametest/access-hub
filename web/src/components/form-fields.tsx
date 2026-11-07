"use client";

import type {
  ChangeEvent,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import {
  Children,
  isValidElement,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { Icon } from "@/components/icon";

/**
 * Form primitives matching components/field.tsx styling for the admin dialog
 * forms (selects, textareas, checkbox groups — Field is input-only).
 */

function labelClasses(): string {
  return "mb-1.5 block text-[13px] font-semibold text-white/90";
}

function controlClasses(error?: string | null): string {
  return `w-full rounded-lg border bg-white/[0.06] px-3.5 py-2.5 text-[15px] text-white transition-colors placeholder:text-white/30 focus:outline-none focus:ring-2 disabled:opacity-50 ${
    error
      ? "border-[#FF5630]/60 focus:border-[#FF5630] focus:ring-[#FF5630]/25"
      : "border-white/15 focus:border-ah-accent focus:ring-ah-accent/30"
  }`;
}

export interface SelectFieldProps
  extends Omit<SelectHTMLAttributes<HTMLSelectElement>, "children"> {
  label: string;
  error?: string | null;
  hint?: string;
  children: ReactNode;
}

interface SelectOption {
  value: string;
  label: string;
  disabled: boolean;
}

function nodeToText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(nodeToText).join("");
  if (isValidElement(node)) {
    return nodeToText((node.props as { children?: ReactNode }).children);
  }
  return "";
}

/** Flatten the <option> children into plain {value,label} pairs for the listbox. */
function parseOptions(children: ReactNode): SelectOption[] {
  const options: SelectOption[] = [];
  Children.forEach(children, (child) => {
    if (isValidElement(child) && child.type === "option") {
      const props = child.props as {
        value?: string;
        disabled?: boolean;
        children?: ReactNode;
      };
      const label = nodeToText(props.children);
      options.push({
        value: props.value ?? label,
        label,
        disabled: props.disabled === true,
      });
    }
  });
  return options;
}

type PopupPos = {
  left: number;
  width: number;
  maxHeight: number;
  top?: number;
  bottom?: number;
};

const POPUP_MAX_HEIGHT = 288;

/**
 * Custom listbox select. The native <select> dropdown popup is rendered by the
 * browser outside the page: recent Chromium builds on Windows (fluent-style
 * popup) paint it light and ignore both page color-scheme and option CSS,
 * which left options white-on-white in this dark UI. So the popup is DOM
 * instead: a button trigger + a portal-rendered, fully page-styled list.
 *
 * The public API matches the previous native select (children = <option>
 * elements, onChange receives { target: { value } }) so call sites are
 * unchanged.
 */
export function SelectField({
  label,
  error,
  hint,
  id,
  className = "",
  children,
  value,
  onChange,
  disabled,
  name,
}: SelectFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const listId = `${inputId}-listbox`;

  const options = useMemo(() => parseOptions(children), [children]);
  const valueText = value === undefined ? "" : String(value);
  const selected = options.find((option) => option.value === valueText) ?? null;

  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [pos, setPos] = useState<PopupPos | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const typeahead = useRef<{
    buffer: string;
    timer: ReturnType<typeof setTimeout> | null;
  }>({ buffer: "", timer: null });

  const computePos = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom - 8;
    const spaceAbove = rect.top - 8;
    // Prefer below; flip above when there is no room and above fits better.
    const openUp = spaceBelow < 140 && spaceAbove > spaceBelow;
    setPos({
      left: rect.left,
      width: rect.width,
      maxHeight: Math.max(
        96,
        Math.min(POPUP_MAX_HEIGHT, openUp ? spaceAbove : spaceBelow),
      ),
      ...(openUp
        ? { bottom: window.innerHeight - rect.top + 6 }
        : { top: rect.bottom + 6 }),
    });
  }, []);

  const commit = (option: SelectOption | undefined) => {
    if (!option || option.disabled) return;
    setOpen(false);
    // Same event shape as the native select so existing onChange handlers
    // ((event) => event.target.value) keep working.
    onChange?.({
      target: { value: option.value, name },
    } as unknown as ChangeEvent<HTMLSelectElement>);
  };

  const openList = () => {
    if (disabled || open || options.length === 0) return;
    const start = Math.max(
      0,
      options.findIndex((option) => option.value === valueText),
    );
    setActiveIndex(start);
    computePos();
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;

    // Document-level (capture) so it also works when focus leaves the trigger,
    // and so Escape can be swallowed before the Dialog/Drawer sees it.
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setOpen(false);
        return;
      }
      if (event.key === "Tab") {
        setOpen(false);
        return;
      }
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        commit(options[activeIndex]);
        return;
      }
      const move = (delta: number) => {
        event.preventDefault();
        setActiveIndex((current) => {
          let next = current;
          for (let step = 0; step < options.length; step += 1) {
            next = (next + delta + options.length) % options.length;
            if (!options[next].disabled) break;
          }
          return next;
        });
      };
      switch (event.key) {
        case "ArrowDown":
          move(1);
          return;
        case "ArrowUp":
          move(-1);
          return;
        case "Home": {
          event.preventDefault();
          setActiveIndex(Math.max(0, options.findIndex((o) => !o.disabled)));
          return;
        }
        case "End": {
          event.preventDefault();
          setActiveIndex(options.length - 1 - [...options].reverse().findIndex((o) => !o.disabled));
          return;
        }
        default: {
          // Type-ahead: jump to the next option whose label starts with the
          // buffered characters (cleared after a short pause).
          if (event.key.length === 1 && !event.altKey && !event.ctrlKey && !event.metaKey) {
            event.preventDefault();
            const state = typeahead.current;
            if (state.timer) clearTimeout(state.timer);
            state.buffer += event.key.toLowerCase();
            state.timer = setTimeout(() => {
              state.buffer = "";
            }, 450);
            const query = state.buffer;
            const matches = (option: SelectOption) =>
              !option.disabled && option.label.toLowerCase().startsWith(query);
            const after = options.findIndex(
              (option, index) => index > activeIndex && matches(option),
            );
            const fromStart = options.findIndex(matches);
            if (after >= 0) setActiveIndex(after);
            else if (fromStart >= 0) setActiveIndex(fromStart);
          }
        }
      }
    };

    const onMouseDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (triggerRef.current?.contains(target) || listRef.current?.contains(target)) {
        return;
      }
      setOpen(false);
    };

    const onReposition = () => computePos();

    document.addEventListener("keydown", onKeyDown, true);
    document.addEventListener("mousedown", onMouseDown);
    // scroll does not bubble but does capture — catches dialog/drawer scrolls.
    window.addEventListener("scroll", onReposition, true);
    window.addEventListener("resize", onReposition);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      document.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("scroll", onReposition, true);
      window.removeEventListener("resize", onReposition);
      const state = typeahead.current;
      if (state.timer) clearTimeout(state.timer);
      state.buffer = "";
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, options, activeIndex, computePos]);

  // Keep the keyboard-active option visible while navigating.
  useEffect(() => {
    if (!open || activeIndex < 0) return;
    listRef.current?.children[activeIndex]?.scrollIntoView({ block: "nearest" });
  }, [open, activeIndex]);

  return (
    <div className={className}>
      <label htmlFor={inputId} className={labelClasses()}>
        {label}
      </label>
      <button
        ref={triggerRef}
        id={inputId}
        type="button"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-invalid={error ? true : undefined}
        aria-activedescendant={
          open && activeIndex >= 0 ? `${listId}-opt-${activeIndex}` : undefined
        }
        onClick={() => (open ? setOpen(false) : openList())}
        onKeyDown={(event) => {
          if (open) return; // handled by the document-level listener
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            openList();
          }
        }}
        className={`flex cursor-pointer items-center justify-between gap-2 text-left ${controlClasses(error)}`}
      >
        <span className={`truncate ${selected ? "" : "text-white/30"}`}>
          {selected ? selected.label : valueText || "Select…"}
        </span>
        <Icon
          name="chevron-down"
          className={`size-4 flex-none text-white/50 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {hint && !error && <p className="mt-1.5 text-xs text-white/45">{hint}</p>}
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}

      {open &&
        pos &&
        createPortal(
          <div
            ref={listRef}
            id={listId}
            role="listbox"
            aria-label={label}
            className="z-[70] overflow-y-auto rounded-xl border border-white/10 bg-[#0B4343] py-1.5 shadow-[0_16px_40px_-8px_rgba(0,0,0,0.65)]"
            style={{
              position: "fixed",
              left: pos.left,
              width: pos.width,
              maxHeight: pos.maxHeight,
              top: pos.top,
              bottom: pos.bottom,
            }}
          >
            {options.map((option, index) => {
              const isSelected = option.value === valueText;
              const isActive = index === activeIndex;
              return (
                <button
                  key={option.value || index}
                  id={`${listId}-opt-${index}`}
                  type="button"
                  role="option"
                  aria-selected={isSelected}
                  disabled={option.disabled}
                  // Keep focus on the trigger so keyboard handling stays put.
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => commit(option)}
                  onMouseEnter={() => setActiveIndex(index)}
                  className={`flex w-full items-center gap-2 px-3.5 py-2 text-left text-[15px] transition-colors ${
                    option.disabled
                      ? "cursor-not-allowed text-white/30"
                      : isSelected
                        ? "bg-ah-accent/20 font-semibold text-white"
                        : isActive
                          ? "bg-white/[0.07] text-white"
                          : "text-white/80 hover:bg-white/[0.07] hover:text-white"
                  }`}
                >
                  <span className="min-w-0 flex-1 truncate">{option.label}</span>
                  {isSelected && (
                    <Icon name="check" className="size-4 flex-none text-ah-accent" />
                  )}
                </button>
              );
            })}
          </div>,
          document.body,
        )}
    </div>
  );
}

export interface TextareaFieldProps
  extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string;
  error?: string | null;
  hint?: string;
  monospace?: boolean;
}

export function TextareaField({
  label,
  error,
  hint,
  monospace = false,
  id,
  className = "",
  ...rest
}: TextareaFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const hintId = `${inputId}-hint`;
  return (
    <div className={className}>
      <label htmlFor={inputId} className={labelClasses()}>
        {label}
      </label>
      <textarea
        id={inputId}
        aria-invalid={error ? true : undefined}
        aria-describedby={hint ? hintId : undefined}
        className={`${controlClasses(error)} ${monospace ? "font-mono text-[13px] leading-relaxed" : ""}`}
        {...rest}
      />
      {hint && !error && (
        <p id={hintId} className="mt-1.5 text-xs text-white/45">
          {hint}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}
    </div>
  );
}

/**
 * Checkbox group for multi-selects (role pickers, grant types). Renders a
 * scrollable bordered list; empty state shows a friendly hint.
 */
export function CheckboxList({
  label,
  options,
  selected,
  onToggle,
  error,
  emptyHint = "Nothing to choose from yet.",
  maxH = "max-h-44",
}: {
  label: string;
  options: { value: string; label: string; detail?: string }[];
  selected: string[];
  onToggle: (value: string) => void;
  error?: string | null;
  emptyHint?: string;
  maxH?: string;
}) {
  const toggle = (event: ChangeEvent<HTMLInputElement>) => {
    onToggle(event.target.value);
  };
  return (
    <div>
      <span className={labelClasses()}>{label}</span>
      <div
        className={`${maxH} overflow-y-auto rounded-lg border border-white/15 bg-white/[0.06] p-1.5`}
      >
        {options.length === 0 && (
          <p className="px-2.5 py-2 text-[13px] text-white/45">{emptyHint}</p>
        )}
        {options.map((option) => {
          const checked = selected.includes(option.value);
          return (
            <label
              key={option.value}
              className={`flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors hover:bg-white/[0.06] ${
                checked ? "text-white" : "text-white/70"
              }`}
            >
              <input
                type="checkbox"
                value={option.value}
                checked={checked}
                onChange={toggle}
                className="size-4 flex-none accent-[#54B3B3]"
              />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-semibold">{option.label}</span>
                {option.detail && (
                  <span className="block truncate text-xs text-white/45">
                    {option.detail}
                  </span>
                )}
              </span>
            </label>
          );
        })}
      </div>
      {error && (
        <p role="alert" className="mt-1.5 text-xs text-[#FF9C86]">
          {error}
        </p>
      )}
    </div>
  );
}
