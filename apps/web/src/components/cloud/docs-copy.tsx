import React from "react";

/** Documentation sentences for a self-hosted installation (no plans, no Cloud billing). */

export function DocsPlanNote() {
  return (
    <>
      Note: this installation is activated once its owner has accepted the licences. The first 1,000 cryptographic operations are free for life; see Licence and usage in the console.
    </>
  );
}

export function DocsBillingFact() {
  return <>licensed and lifetime operation counts</>;
}
