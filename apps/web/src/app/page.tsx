"use client";

import { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";

/** A self-hosted installation has no marketing site: the front door is the sign-in page. */
export default function HomePage() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/login/");
  }, [router]);

  return (
    <main className="min-h-screen flex items-center justify-center bg-[#F8F7F4] text-sm text-[#636863]">
      <p>
        Redirecting to the sign-in page.{" "}
        <Link href="/login/" className="text-[#008031] underline">
          Continue
        </Link>
      </p>
    </main>
  );
}
