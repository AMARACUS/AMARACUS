"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Modal } from "@/components/ui/modal";
import { Shield, ArrowRight } from "lucide-react";
import { AUTH_MODAL_BADGE, AUTH_MODAL_BLURB } from "@/components/cloud/auth-modal-copy";

interface AuthRequiredModalProps {
  isOpen: boolean;
  onClose: () => void;
  actionName?: string;
}

export function AuthRequiredModal({
  isOpen,
  onClose,
  actionName = "perform this action",
}: AuthRequiredModalProps) {
  const pathname = usePathname();
  const redirectQuery = pathname ? `?redirect=${encodeURIComponent(pathname)}` : "";

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Account Required"
      description={`To ${actionName}, please sign in or create an account.`}
      maxWidth="max-w-md"
    >
      <div className="space-y-4 pt-1">
        <div className="p-3.5 rounded-xl border border-[#C8E0CF] bg-[#EAF3EC] text-xs flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-white border border-[#C8E0CF] flex items-center justify-center text-[#008031] shrink-0 mt-0.5">
            <Shield className="w-4 h-4 fill-[#008031]/20 stroke-[#008031]" />
          </div>
          <div className="space-y-1">
            <div className="font-semibold text-[#1A1A1A] flex items-center gap-1.5">
              <span>AMARACUS Account</span>
              <span className="text-[10px] text-[#008031] bg-white px-1.5 py-0.5 rounded border border-[#C8E0CF] font-bold">
                {AUTH_MODAL_BADGE}
              </span>
            </div>
            <p className="text-[11px] text-[#636863] leading-relaxed">
              {AUTH_MODAL_BLURB}
            </p>
          </div>
        </div>

        <div className="space-y-2 pt-1">
          <Link
            href={`/signup${redirectQuery}`}
            onClick={onClose}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-[#008031] hover:bg-[#006e2a] text-white font-semibold text-xs transition-colors shadow-xs"
          >
            <span>Create Account</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>

          <Link
            href={`/login${redirectQuery}`}
            onClick={onClose}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg border border-[#E9EDE7] bg-white hover:bg-[#FAF9F6] text-[#1A1A1A] font-medium text-xs transition-colors"
          >
            <span>Sign In to Existing Account</span>
          </Link>
        </div>

        <div className="pt-2 border-t border-[#E9EDE7] text-center">
          <button
            type="button"
            onClick={onClose}
            className="text-[11px] text-[#767676] hover:text-[#1A1A1A] transition-colors"
          >
            Continue exploring as guest &rarr;
          </button>
        </div>
      </div>
    </Modal>
  );
}
