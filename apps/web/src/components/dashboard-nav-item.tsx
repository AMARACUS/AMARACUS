"use client";

import React from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";

export function NavItem({ href, icon, label, badge, currentPath }: { href: string; icon: React.ReactNode; label: string; badge?: string; currentPath: string }) {
  const isActive = currentPath === href;
  return (
    <Link
      href={href}
      aria-current={isActive ? "page" : undefined}
      className={cn(
        "flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all duration-150",
        isActive
          ? "bg-[#EAF3EC] text-[#008031] font-semibold"
          : "text-[#555555] hover:bg-[#F3F2EE] hover:text-[#1A1A1A]"
      )}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        <span className={cn(isActive ? "text-[#008031]" : "text-[#767676]")} aria-hidden="true">{icon}</span>
        <span className="truncate">{label}</span>
      </div>
      {badge && (
        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full bg-[#E8F5E9] text-[#008031] border border-[#C8E6C9] shrink-0">
          {badge}
        </span>
      )}
    </Link>
  );
}
