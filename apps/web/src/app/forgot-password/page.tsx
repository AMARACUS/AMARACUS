"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { Shield, Loader2, AlertCircle, CheckCircle2, ArrowLeft, Mail, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api-client";
import { sanitizeText } from "@/lib/sanitize";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successInfo, setSuccessInfo] = useState<{ message: string; resetLink?: string } | null>(null);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const emailParam = params.get("email");
      if (emailParam) setEmail(emailParam);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessInfo(null);

    const safeEmail = sanitizeText(email).toLowerCase().trim();
    if (!safeEmail || !safeEmail.includes("@")) {
      setError("Please enter a valid work email address.");
      return;
    }

    setLoading(true);
    try {
      const res = await api.auth.forgotPassword({ email: safeEmail });
      setSuccessInfo({
        message: res.message || "A password reset link has been sent to your email.",
        resetLink: res.resetLink,
      });
    } catch (err: any) {
      setError(err.message || "Failed to process request. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-center items-center px-6 bg-[#F8F7F4]">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-2 mb-4">
            <div className="w-9 h-9 rounded-lg bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031]">
              <Shield className="w-5 h-5 fill-[#008031]/20 stroke-[#008031]" />
            </div>
            <span className="font-editorial text-2xl font-bold tracking-tight text-[#1A1A1A]">
              AMARACUS
            </span>
          </Link>
          <h1 className="text-lg font-semibold text-[#1A1A1A]">Forgot your password?</h1>
          <p className="text-xs text-[#636863] mt-1">
            We will send a secure password reset link to your email address.
          </p>
        </div>

        <div className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successInfo ? (
            <div className="space-y-4">
              <div className="p-3.5 rounded-xl border border-emerald-200 bg-emerald-50 text-emerald-800 flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 mt-0.5" />
                <div className="space-y-1">
                  <div className="font-semibold text-xs text-emerald-950">Reset Link Sent</div>
                  <div className="text-[11px] text-emerald-800 leading-relaxed">
                    {successInfo.message}
                  </div>
                  <p className="text-[10px] text-emerald-700 pt-1">
                    Please check your inbox (and spam folder) for the link from AMARACUS.
                  </p>
                </div>
              </div>

              {successInfo.resetLink && (
                <a
                  href={successInfo.resetLink}
                  className="w-full p-3 rounded-xl border border-emerald-300 bg-[#EAF3EC] hover:bg-[#DDF0E1] text-[#008031] font-semibold text-xs transition-colors flex items-center justify-between shadow-xs"
                >
                  <div className="flex items-center gap-2">
                    <Mail className="w-4 h-4" />
                    <span>Open Reset Link (Sandbox)</span>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              )}

              <div className="pt-2 text-center border-t border-[#E9EDE7]">
                <button
                  type="button"
                  onClick={() => setSuccessInfo(null)}
                  className="text-[11px] text-[#767676] hover:text-[#1A1A1A] underline"
                >
                  Didn&apos;t receive it? Try another email
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label htmlFor="forgot-email" className="font-medium text-[#1A1A1A]">Email</label>
                <Input
                  id="forgot-email"
                  autoComplete="email"
                  type="email"
                  placeholder="name@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading}
                  autoFocus
                  required
                />
                <p className="text-[11px] text-[#767676]">
                  Enter the email address registered with your account.
                </p>
              </div>

              <Button
                type="submit"
                className="w-full mt-2 bg-[#008031] hover:bg-[#006e2a] text-white"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Dispatching Link...
                  </>
                ) : (
                  <>
                    Send Password Reset Link <Mail className="w-3.5 h-3.5 ml-1.5" />
                  </>
                )}
              </Button>
            </form>
          )}

          <div className="pt-2 border-t border-[#E9EDE7] flex items-center justify-center">
            <Link
              href="/login"
              className="inline-flex items-center gap-1 text-[11px] text-[#767676] hover:text-[#1A1A1A] transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to sign in</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
