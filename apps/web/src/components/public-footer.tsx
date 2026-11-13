"use client";

import React from "react";
import Link from "next/link";
import { Shield } from "lucide-react";

export function PublicFooter() {
  return (
    <footer className="border-t border-[#E9EDE7] bg-white py-10 text-sm text-[#636863]">
      <div className="max-w-6xl mx-auto px-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-[#1A1A1A] font-editorial text-lg font-bold">
          <Shield className="w-4 h-4 text-[#008031]" aria-hidden="true" /> AMARACUS
        </div>
        <ul className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
          <li><Link href="/docs/" className="hover:text-[#008031]">Documentation</Link></li>
          <li><Link href="/dashboard" className="hover:text-[#008031]">Console</Link></li>
          <li><Link href="/dashboard/billing" className="hover:text-[#008031]">Licence and usage</Link></li>
        </ul>
      </div>
    </footer>
  );
}
