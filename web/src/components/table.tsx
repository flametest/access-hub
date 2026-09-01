"use client";

import { Fragment, type ReactNode } from "react";

/**
 * Minimal admin table: sticky header, zebra rows, horizontal scroll on
 * overflow. Columns are declared as data; cells are rendered by the `cell`
 * render prop so pages keep full control of their content.
 */
export interface TableColumn {
  key: string;
  header: ReactNode;
  /** Applied to both th and td (widths, alignment, truncation...). */
  className?: string;
}

export function Table<T>({
  columns,
  rows,
  rowKey,
  cell,
  onRowClick,
  expandable,
  className = "",
}: {
  columns: TableColumn[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  cell: (row: T, column: TableColumn, index: number) => ReactNode;
  onRowClick?: (row: T) => void;
  /** Renders the full-width detail row directly under a row when it returns content. */
  expandable?: (row: T) => ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`overflow-x-auto rounded-2xl border border-white/10 bg-white/[0.06] shadow-[0_12px_24px_-8px_rgba(0,0,0,0.35)] ${className}`}
    >
      <table className="w-full min-w-max border-collapse text-sm">
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                className={`sticky top-0 z-10 whitespace-nowrap border-b border-white/10 bg-[#0B4343]/95 px-4 py-3 text-left text-xs font-bold uppercase tracking-wide text-white/55 backdrop-blur ${column.className ?? ""}`}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => {
            const detail = expandable?.(row);
            const key = rowKey(row, index);
            return (
              <Fragment key={key}>
                <tr
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  className={`border-b border-white/[0.05] transition-colors last:border-b-0 ${
                    index % 2 === 1 ? "bg-white/[0.03]" : ""
                  } ${onRowClick ? "cursor-pointer hover:bg-white/[0.07]" : "hover:bg-white/[0.05]"}`}
                >
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={`px-4 py-3 align-middle text-white/85 ${column.className ?? ""}`}
                    >
                      {cell(row, column, index)}
                    </td>
                  ))}
                </tr>
                {detail !== undefined && detail !== null && (
                  <tr className="border-b border-white/[0.05] last:border-b-0">
                    <td colSpan={columns.length} className="px-4 py-3">
                      {detail}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Loading skeleton matching the table frame. */
export function TableSkeleton({
  rows = 5,
  className = "",
}: {
  rows?: number;
  className?: string;
}) {
  return (
    <div
      aria-hidden="true"
      className={`overflow-hidden rounded-2xl border border-white/10 bg-white/[0.04] ${className}`}
    >
      <div className="h-11 border-b border-white/10 bg-white/[0.04]" />
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className="h-[46px] animate-pulse border-b border-white/[0.05] last:border-b-0"
        />
      ))}
    </div>
  );
}
