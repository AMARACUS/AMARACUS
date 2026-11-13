# AMARACUS pricing

Effective 12 November 2026. Prices are in US dollars and exclude taxes. The amounts below are the ones in the
code (`apps/api/src/lib/billing-plans.ts`); if the two ever differ, the price you were shown when you
bought governs your purchase.

## Self-hosted AMARACUS

| | |
| --- | --- |
| First 1,000 successful billable operations | Free, once, for the lifetime of your corporate group |
| Operation 1,001 onwards | **USD 0.15 per 1,000 operations** (USD 150 per million) |
| How you pay | Prepaid licence keys, each covering a number of operations you choose |
| Who pays | Everyone above the allowance: individuals, students, startups, companies, banks, enterprises |

- The allowance is **lifetime and cumulative**, not monthly. It never renews.
- **One allowance per corporate group**: all employees, subsidiaries, affiliates, projects, environments,
  installations and servers share it. Reinstalling or adding servers does not reset it.
- The rate is the same as the AMARACUS Cloud Pay As You Go rate.
- What counts as a billable operation is defined in section 5 of
  [AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md). Failed operations,
  health checks, console use and idempotent retries are not counted.
- To buy a licence key, write to **legal@amaracus.tech** with your corporate group's legal name and the
  number of operations. Price = operations ÷ 1,000 × USD 0.15.
- Your installation verifies the key offline. Nothing is reported to AMARACUS.

## AMARACUS Cloud (hosted at amaracus.tech)

AMARACUS Cloud has exactly four plans and **no free plan**. The self-hosted lifetime allowance does not apply
to Cloud, and self-hosted licence keys cannot be used there.

| Plan | Price | Included operations per month | Then |
| --- | --- | --- | --- |
| Starter | USD 2 / month | 15,000 | operations stop, unless you authorize paid overage up to a cap |
| Pro | USD 20 / month | 150,000 | operations stop, unless you authorize paid overage up to a cap |
| Business | USD 99 / month | 1,000,000 | operations stop, unless you authorize paid overage up to a cap |
| Pay As You Go | no monthly fee | none | USD 0.15 per 1,000 operations, up to a spending cap you set |

Cloud plan limits, features and terms are on [amaracus.tech/pricing](https://amaracus.tech/pricing) and in
the AMARACUS Cloud Terms of Service.
