import Link from "next/link";
import { Button } from "@/components/ui/button";
import { ShieldAlert } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-[#F8F7F4] text-center">
      <div className="w-14 h-14 rounded-full bg-[#EAF3EC] text-[#008031] flex items-center justify-center mb-4">
        <ShieldAlert className="w-7 h-7" />
      </div>
      <h1 className="font-editorial text-4xl font-bold text-[#1A1A1A] mb-2">404 - Page Not Found</h1>
      <p className="text-sm text-[#555555] max-w-sm mb-6 leading-relaxed">
        The cryptographic resource or interface you requested does not exist or has been relocated under policy governance.
      </p>
      <div className="flex gap-3">
        <Link href="/">
          <Button variant="outline">Return Home</Button>
        </Link>
        <Link href="/dashboard">
          <Button>Open Console</Button>
        </Link>
      </div>
    </div>
  );
}
