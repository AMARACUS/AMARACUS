"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Loader2, AlertCircle, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/lib/auth-context";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [redirectUrl, setRedirectUrl] = useState("/dashboard");
  const [signupLink, setSignupLink] = useState("/signup");

  React.useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const redirectParam = params.get("redirect");
      if (redirectParam) {
        setRedirectUrl(redirectParam);
        setSignupLink(`/signup?redirect=${encodeURIComponent(redirectParam)}`);
      }
      if (params.get("reset") === "success") {
        setSuccessMessage("Your password has been reset successfully. Please sign in with your new password.");
      }
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email.trim() || !password.trim()) {
      setError("Please enter both email and password.");
      return;
    }

    setLoading(true);
    try {
      await login({ email: email.trim(), password });
      router.push(redirectUrl);
    } catch (err: any) {
      setError(err.message || "Failed to sign in. Please verify your credentials.");
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
          <h1 className="text-lg font-semibold text-[#1A1A1A]">Sign in to Console</h1>
          <p className="text-xs text-[#636863] mt-1">Enter your email and password</p>
        </div>

        <div className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-4 text-xs">
          {successMessage && (
            <div className="p-3 rounded-lg border border-emerald-200 bg-emerald-50 text-emerald-800 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{successMessage}</span>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}


          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="login-email" className="font-medium text-[#1A1A1A]">Email</label>
              <Input
                id="login-email"
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
              <div className="flex justify-between items-center">
                <label htmlFor="login-password" className="font-medium text-[#1A1A1A]">Password</label>
                <Link
                  href={email.trim() ? `/forgot-password?email=${encodeURIComponent(email.trim())}` : "/forgot-password"}
                  className="text-[11px] text-[#008031] hover:underline font-medium"
                >
                  Forgot password?
                </Link>
              </div>
              <Input
                id="login-password"
                autoComplete="current-password"
                type="password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                required
              />
            </div>

            <Button type="submit" className="w-full mt-2" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Authenticating...
                </>
              ) : (
                "Sign In"
              )}
            </Button>
          </form>
        </div>

        <p className="text-center text-xs text-[#767676] mt-6">
          Don&apos;t have an account?{" "}
          <Link href={signupLink} className="text-[#008031] font-medium hover:underline">
            Create account
          </Link>
        </p>
      </div>
    </div>
  );
}