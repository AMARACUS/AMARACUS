"use client";

import React from "react";

/**
 * Sign-up copy for a self-hosted installation. It replaces the AMARACUS Cloud version: there are no plans and
 * no Cloud Terms of Service here. The installation's owner accepts the two licences when activating it.
 */

/** There are no plans to pick on a self-hosted installation. */
export const SIGNUP_PLAN_LABELS: Record<string, string> = {};

export const SIGNUP_DEFAULT_REDIRECT = "/dashboard";

/** Plan links make no sense here, so the normal redirect is used. */
export function signupPlanRedirect(_plan: string): string | null {
  return null;
}

export function signupIntro(_selectedPlan: string | null): string {
  return "Create your account on this installation.";
}

export const SIGNUP_AGE_ERROR = "Please confirm that you are authorised to create an account on this installation.";
export const SIGNUP_TERMS_ERROR = "Please confirm that you are authorised to create an account on this installation.";

export interface SignupConsentsProps {
  loading: boolean;
  ageConfirmed: boolean;
  setAgeConfirmed: (value: boolean) => void;
  termsAccepted: boolean;
  setTermsAccepted: (value: boolean) => void;
  marketingOptIn: boolean;
  setMarketingOptIn: (value: boolean) => void;
  clearError: () => void;
}

export function SignupConsents({ loading, ageConfirmed, setAgeConfirmed, setTermsAccepted, clearError }: SignupConsentsProps) {
  return (
    <div className="pt-1 pb-1">
      <div className="p-3 rounded-xl border border-[#E9EDE7] bg-[#FAF9F6]">
        <label className="flex items-start gap-2.5 cursor-pointer text-[#636863] select-none text-[11px] leading-relaxed">
          <input
            type="checkbox"
            checked={ageConfirmed}
            onChange={(e) => {
              setAgeConfirmed(e.target.checked);
              setTermsAccepted(e.target.checked);
              clearError();
            }}
            disabled={loading}
            className="mt-0.5 rounded border-[#C8E0CF] text-[#008031] focus:ring-[#008031]"
            required
          />
          <span>
            <strong className="text-[#1A1A1A] font-medium">I am authorised to create an account on this installation.</strong>{" "}
            The licence terms for this installation are accepted by its owner when it is activated.
          </span>
        </label>
      </div>
    </div>
  );
}
