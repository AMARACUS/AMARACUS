"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Shield, Loader2, AlertCircle, Mail, ArrowLeft, CheckCircle2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/lib/auth-context";
import { safeRedirectPath } from "@/lib/safe-redirect";
import { sanitizeText } from "@/lib/sanitize";
import {
  SIGNUP_AGE_ERROR,
  SIGNUP_DEFAULT_REDIRECT,
  SIGNUP_PLAN_LABELS,
  SIGNUP_TERMS_ERROR,
  SignupConsents,
  signupIntro,
  signupPlanRedirect,
} from "@/components/cloud/signup-consents";

const SIGNUP_DRAFT_KEY = "amaracus_signup_draft";

export default function SignupPage() {
  const router = useRouter();
  const { sendSignupOtp, verifySignupOtp, resendSignupOtp } = useAuth();

  // Step state: 'form' | 'otp'
  const [step, setStep] = useState<"form" | "otp">("form");

  // Form fields
  const [name, setName] = useState("");
  const [org, setOrg] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [marketingOptIn, setMarketingOptIn] = useState(false);

  // Age confirmation (13+ requirement - students welcome)
  const [ageConfirmed, setAgeConfirmed] = useState(false);

  // OTP state
  const [otp, setOtp] = useState("");
  const [resendCooldown, setResendCooldown] = useState(0);

  // UI states
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  // After signing up, the next stop (a plan on AMARACUS Cloud, the console when self-hosted).
  const [redirectUrl, setRedirectUrl] = useState(SIGNUP_DEFAULT_REDIRECT);
  const [signinLink, setSigninLink] = useState("/login");
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);

  // Name, organization and email survive a trip to another page and back (never the password).
  const draftLoaded = useRef(false);
  useEffect(() => {
    try {
      const draft = JSON.parse(sessionStorage.getItem(SIGNUP_DRAFT_KEY) || "null");
      if (draft) {
        if (typeof draft.name === "string") setName(draft.name);
        if (typeof draft.org === "string") setOrg(draft.org);
        if (typeof draft.email === "string") setEmail(draft.email);
      }
    } catch {
      // Unreadable or blocked storage: start with an empty form.
    }
    draftLoaded.current = true;
  }, []);
  useEffect(() => {
    if (!draftLoaded.current) return;
    try {
      sessionStorage.setItem(SIGNUP_DRAFT_KEY, JSON.stringify({ name, org, email }));
    } catch {
      // Storage unavailable (private mode quotas): the form still works.
    }
  }, [name, org, email]);

  // Clear any legacy screening blocks & detect upgrade/plan params
  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("amaracus_underage_screened");
      const params = new URLSearchParams(window.location.search);
      const plan = params.get("plan");
      const redirect = safeRedirectPath(params.get("redirect"));
      const basePlanRedirect = plan ? signupPlanRedirect(plan.toUpperCase()) : null;
      // A yearly choice on the pricing page carries through to checkout.
      const planRedirect =
        basePlanRedirect && params.get("interval") === "year" && basePlanRedirect.includes("?")
          ? `${basePlanRedirect}&interval=year`
          : basePlanRedirect;
      if (plan && planRedirect) {
        if (SIGNUP_PLAN_LABELS[plan.toUpperCase()]) setSelectedPlan(plan.toUpperCase());
        setRedirectUrl(planRedirect);
        setSigninLink(`/login?redirect=${encodeURIComponent(planRedirect)}`);
      } else if (redirect) {
        setRedirectUrl(redirect);
        setSigninLink(`/login?redirect=${encodeURIComponent(redirect)}`);
      }
    }
  }, []);

  // Resend cooldown timer
  useEffect(() => {
    if (resendCooldown <= 0) return;
    const timer = setInterval(() => {
      setResendCooldown((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => clearInterval(timer);
  }, [resendCooldown]);

  // Step 1: Send OTP
  const handleInitiateSignup = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfoMessage(null);

    if (!ageConfirmed) {
      setError(SIGNUP_AGE_ERROR);
      return;
    }

    const safeName = sanitizeText(name);
    const safeOrg = sanitizeText(org);
    const safeEmail = sanitizeText(email).toLowerCase();

    if (!safeName || !safeEmail || !password.trim()) {
      setError("Please fill in your name, email and password.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    if (!termsAccepted) {
      setError(SIGNUP_TERMS_ERROR);
      return;
    }

    setLoading(true);
    try {
      await sendSignupOtp({
        email: safeEmail,
        password,
        name: safeName,
        organizationName: safeOrg || undefined,
        termsAccepted: true,
        marketingOptIn,
        ageAttested: true,
      });

      setStep("otp");
      setResendCooldown(60);
      setInfoMessage(`We've sent a 6-digit verification code to ${safeEmail}`);
    } catch (err: any) {
      setError(err.message || "Failed to start registration. Please check your information.");
    } finally {
      setLoading(false);
    }
  };

  // Step 2: Verify OTP
  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfoMessage(null);

    if (!otp.trim() || otp.trim().length !== 6) {
      setError("Please enter a valid 6-digit verification code.");
      return;
    }

    setLoading(true);
    try {
      await verifySignupOtp({
        email: email.trim().toLowerCase(),
        otp: otp.trim(),
      });
      try {
        sessionStorage.removeItem(SIGNUP_DRAFT_KEY);
      } catch {
        // Nothing to clear.
      }
      router.push(redirectUrl);
    } catch (err: any) {
      setError(err.message || "Invalid or expired verification code.");
    } finally {
      setLoading(false);
    }
  };

  // Resend OTP
  const handleResendOtp = async () => {
    if (resendCooldown > 0 || loading) return;
    setError(null);
    setLoading(true);
    try {
      await resendSignupOtp(email.trim().toLowerCase());
      setResendCooldown(60);
      setInfoMessage("A fresh verification code has been dispatched to your email.");
    } catch (err: any) {
      setError(err.message || "Failed to resend code.");
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
          <h1 className="text-lg font-semibold text-[#1A1A1A]">
            Create your account
          </h1>
          <p className="text-xs text-[#636863] mt-1">
            {signupIntro(selectedPlan)}
          </p>
        </div>

        {step === "otp" ? (
          <form onSubmit={handleVerifyOtp} className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-4 text-xs">
            {error && (
              <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {infoMessage && (
              <div className="p-3 rounded-lg border border-[#C8E0CF] bg-[#EAF3EC] text-[#008031] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{infoMessage}</span>
              </div>
            )}

            <div className="text-center py-2">
              <div className="w-12 h-12 rounded-full bg-[#EAF3EC] border border-[#C8E0CF] flex items-center justify-center text-[#008031] mx-auto mb-3">
                <Mail className="w-6 h-6" />
              </div>
              <p className="text-xs text-[#636863]">
                Enter the 6-digit verification code sent to:
              </p>
              <p className="font-semibold text-sm text-[#1A1A1A] mt-0.5">{email}</p>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="signup-otp" className="font-medium text-[#1A1A1A]">6-Digit Verification Code</label>
              <Input
                id="signup-otp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder="123456"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, "").slice(0, 6))}
                disabled={loading}
                className="text-center text-lg tracking-widest font-mono"
                maxLength={6}
                autoFocus
                required
              />
            </div>

            <Button
              type="submit"
              className="w-full mt-2"
              disabled={loading || otp.length !== 6}
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Verifying...
                </>
              ) : (
                "Verify & Activate Account"
              )}
            </Button>

            <div className="flex items-center justify-between pt-2 text-xs">
              <button
                type="button"
                onClick={() => setStep("form")}
                className="text-[#636863] hover:text-[#1A1A1A] flex items-center gap-1"
                disabled={loading}
              >
                <ArrowLeft className="w-3 h-3" /> Back
              </button>
              <button
                type="button"
                onClick={handleResendOtp}
                disabled={resendCooldown > 0 || loading}
                className={`flex items-center gap-1 ${
                  resendCooldown > 0
                    ? "text-[#8C928C] cursor-not-allowed"
                    : "text-[#008031] hover:underline font-medium"
                }`}
              >
                <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
                {resendCooldown > 0 ? `Resend code (${resendCooldown}s)` : "Resend code"}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleInitiateSignup} className="p-6 rounded-2xl border border-[#E9EDE7] bg-white shadow-card space-y-4 text-xs">
          {error && (
            <div className="p-3 rounded-lg border border-red-200 bg-red-50 text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="space-y-1.5">
            <label htmlFor="signup-name" className="font-medium text-[#1A1A1A]">Full Name</label>
            <Input
              id="signup-name"
              autoComplete="name"
              type="text"
              placeholder="Ada Lovelace"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="signup-org" className="font-medium text-[#1A1A1A]">Organization Name <span className="font-normal text-[#767676]">(optional)</span></label>
            <Input
              id="signup-org"
              autoComplete="organization"
              type="text"
              placeholder="Acme Security Corp"
              value={org}
              onChange={(e) => setOrg(e.target.value)}
              disabled={loading}
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="signup-email" className="font-medium text-[#1A1A1A]">Email</label>
            <Input
              id="signup-email"
              autoComplete="email"
              type="email"
              placeholder="ada@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div className="space-y-1.5">
            <label htmlFor="signup-password" className="font-medium text-[#1A1A1A]">Password</label>
            <Input
              id="signup-password"
              autoComplete="new-password"
              minLength={8}
              type="password"
              placeholder="At least 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <SignupConsents
            loading={loading}
            ageConfirmed={ageConfirmed}
            setAgeConfirmed={setAgeConfirmed}
            termsAccepted={termsAccepted}
            setTermsAccepted={setTermsAccepted}
            marketingOptIn={marketingOptIn}
            setMarketingOptIn={setMarketingOptIn}
            clearError={() => setError(null)}
          />

          <Button
            type="submit"
            className="w-full mt-2"
            disabled={loading || !ageConfirmed || !termsAccepted}
          >
            {loading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Sending Verification Code...
              </>
            ) : (
              "Send Verification Code"
            )}
          </Button>
        </form>
      )}

        <p className="text-center text-xs text-[#767676] mt-6">
          Already have an account?{" "}
          <Link href={signinLink} className="text-[#008031] font-medium hover:underline">
            Sign in
          </Link>
        </p>
      </div>

    </div>
  );
}
