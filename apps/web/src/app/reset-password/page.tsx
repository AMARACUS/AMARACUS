"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Loader2, AlertCircle, ArrowLeft, KeyRound, Lock, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api-client";
import { sanitizeText } from "@/lib/sanitize";

export default function ResetPasswordPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [token, setToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [mounted, setMounted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setMounted(true);
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const emailParam = params.get("email");
      const tokenParam = params.get("token") || params.get("code");
      if (emailParam) setEmail(emailParam);
      if (tokenParam) setToken(tokenParam.trim());
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const safeEmail = sanitizeText(email).toLowerCase().trim();
    const safeToken = token.trim();

    if (!safeEmail || !safeEmail.includes("@")) {
      setError("Please provide a valid email address.");
      return;
    }

    if (!safeToken) {
      setError("Missing or invalid password reset token. Please request a new link.");
      return;
    }

    if (!newPassword || newPassword.length < 8) {
      setError("Your new password must be at least 8 characters long.");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match. Please verify and retype.");
      return;
    }

    setLoading(true);
    try {
      await api.auth.resetPassword({
        email: safeEmail,
        token: safeToken,
        newPassword,
      });

      router.push("/login?reset=success");
    } catch (err: any) {
      setError(err.message || "Failed to reset password. The link may have expired or already been used.");
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
          <h1 className="text-lg font-semibold text-[#1A1A1A]">Set new password</h1>
          <p className="text-xs text-[#636863] mt-1">
            Choose a new secure password for your AMARACUS account.
          </p>
        </div>

        {mounted && !token ? (
          <div className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-4 text-xs">
            <div className="p-3.5 rounded-xl border border-amber-200 bg-amber-50 text-amber-900 flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 text-amber-700 mt-0.5" />
              <div className="space-y-1">
                <div className="font-semibold text-xs text-amber-950">Invalid or Missing Link</div>
                <div className="text-[11px] text-amber-800 leading-relaxed">
                  This password reset link is invalid or incomplete. Please request a new password reset link.
                </div>
              </div>
            </div>

            <Link
              href="/forgot-password"
              className="w-full inline-flex items-center justify-center rounded-lg text-sm font-medium bg-[#008031] hover:bg-[#006827] text-white h-9 px-4 py-2 transition-colors"
            >
              Request New Reset Link
            </Link>

            <div className="pt-2 border-t border-[#E9EDE7] text-center">
              <Link
                href="/login"
                className="text-[11px] text-[#767676] hover:text-[#1A1A1A] transition-colors"
              >
                Back to sign in
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-4 text-xs">
            {error && (
              <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-1.5">
              <label htmlFor="reset-email" className="font-medium text-[#1A1A1A]">Account Email</label>
              <Input
                id="reset-email"
                autoComplete="email"
                type="email"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={loading}
                required
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="reset-new-password" className="font-medium text-[#1A1A1A]">New Password</label>
              <Input
                id="reset-new-password"
                autoComplete="new-password"
                type="password"
                placeholder="At least 8 characters"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled={loading}
                autoFocus
                required
              />
            </div>

            <div className="space-y-1.5">
              <label htmlFor="reset-confirm-password" className="font-medium text-[#1A1A1A]">Confirm New Password</label>
              <Input
                id="reset-confirm-password"
                autoComplete="new-password"
                type="password"
                placeholder="Retype your new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={loading}
                required
              />
            </div>

            <Button
              type="submit"
              className="w-full mt-2 bg-[#008031] hover:bg-[#006e2a] text-white"
              disabled={loading || newPassword.length < 8 || newPassword !== confirmPassword}
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Saving Password...
                </>
              ) : (
                <>
                  Reset Password &amp; Sign In <Lock className="w-3.5 h-3.5 ml-1.5" />
                </>
              )}
            </Button>

            <div className="pt-2 border-t border-[#E9EDE7] flex items-center justify-between text-[11px]">
              <Link
                href="/forgot-password"
                className="text-[#767676] hover:text-[#1A1A1A] flex items-center gap-1"
              >
                <ArrowLeft className="w-3.5 h-3.5" /> Request a new link
              </Link>

              <Link
                href="/login"
                className="text-[#008031] font-medium hover:underline"
              >
                Back to sign in
              </Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
