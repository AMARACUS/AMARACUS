"use client";

import React from "react";
import { useEdition } from "@/lib/edition";
import { CloudBilling } from "@/components/cloud/cloud-billing";
import { SelfHostLicensePanel } from "@/components/selfhost-license-panel";

export default function BillingPage() {
  const { edition } = useEdition();
  // Self-hosted installations have a licence key and a usage ledger instead of plans and checkout.
  if (edition === "selfhosted") return <SelfHostLicensePanel />;
  return <CloudBilling />;
}
