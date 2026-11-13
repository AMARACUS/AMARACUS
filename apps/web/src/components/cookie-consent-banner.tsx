"use client";

import React from "react";
import { CookieSettingsModal } from "./cookie-settings-modal";

/**
 * A self-hosted installation stores only what keeps you signed in, so it shows no consent banner.
 * The preferences dialog stays mounted because Settings can open it.
 */
export function CookieConsentBanner() {
  return <CookieSettingsModal />;
}
