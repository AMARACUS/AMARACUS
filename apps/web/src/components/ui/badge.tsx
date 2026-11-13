import * as React from "react";
import { cn } from "@/lib/utils";

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "outline" | "success" | "warning" | "destructive";
}

function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        "inline-flex items-center rounded-md px-2.5 py-0.5 text-xs font-medium tracking-wide transition-colors",
        {
          "bg-[#EAF3EC] text-[#008031] border border-[#C8E0CF]": variant === "default" || variant === "success",
          "bg-[#F0EFEA] text-[#555555] border border-[#E2E0D8]": variant === "secondary",
          "border border-[#E9EDE7] text-[#1A1A1A] bg-white": variant === "outline",
          "bg-[#FEF8EC] text-[#B45309] border border-[#FDE68A]": variant === "warning",
          "bg-[#FDF2F2] text-[#B91C1C] border border-[#FECACA]": variant === "destructive",
        },
        className
      )}
      {...props}
    />
  );
}

export { Badge };
