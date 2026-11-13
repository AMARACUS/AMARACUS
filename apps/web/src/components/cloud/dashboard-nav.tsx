"use client";

import React from "react";

/** AMARACUS Cloud only. A self-hosted installation has no plan, agents, events or hosting entries here. */
export function CloudOverviewNav(_props: { pathname: string }) {
  return null;
}

export function CloudOperationsNav(_props: { pathname: string }) {
  return null;
}

export function CloudPlanWidget() {
  return null;
}

/** Explains what a signed-out visitor can do in the read-only console preview. */
export function GuestBannerText() {
  return <>You can explore the console. Sign in, or create an account, to create keys and generate API credentials.</>;
}
