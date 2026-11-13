import React from "react";
import { Button } from "./button";

interface EmptyStateProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ icon, title, description, actionLabel, onAction }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl border border-dashed border-[#DCDFD8] bg-white/60">
      <div className="w-12 h-12 rounded-full bg-[#EAF3EC] text-[#008031] flex items-center justify-center mb-4">
        {icon}
      </div>
      <h3 className="text-base font-semibold text-[#1A1A1A] mb-1">{title}</h3>
      <p className="text-sm text-[#636863] max-w-sm mb-6 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <Button onClick={onAction} size="sm">
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
