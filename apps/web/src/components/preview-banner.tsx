import React from "react";
import { AlertTriangle } from "lucide-react";

/**
 * Marks a dashboard area whose feature is a preview: it works for trying things out,
 * but is not production ready. Keep the text specific about what is missing.
 */
export function PreviewBanner({ children }: { children: React.ReactNode }) {
  return (
    <div
      role="note"
      className="flex items-start gap-2.5 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" />
      <div>
        <span className="font-semibold">Preview, not for production use. </span>
        {children}
      </div>
    </div>
  );
}
