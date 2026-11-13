import Link from "next/link";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";

export function PublicHeader() {
  return (
    <header className="sticky top-0 z-50 border-b border-[#E9EDE7] bg-[#F8F7F4]/90 backdrop-blur-md">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031]">
            <Shield className="w-4 h-4 fill-[#008031]/20 stroke-[#008031]" aria-hidden="true" />
          </div>
          <span className="font-editorial text-xl font-bold tracking-tight text-[#1A1A1A]">AMARACUS</span>
        </Link>
        <nav aria-label="Main" className="flex items-center gap-2 sm:gap-4 text-sm font-medium text-[#555555]">
          <Link href="/docs" className="hover:text-[#008031] transition-colors px-2">Documentation</Link>
          <Link href="/login" className="hover:text-[#1A1A1A] transition-colors px-2">Sign In</Link>
          <Link href="/dashboard">
            <Button size="sm" variant="outline">Console</Button>
          </Link>
        </nav>
      </div>
    </header>
  );
}
