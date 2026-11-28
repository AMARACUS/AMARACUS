# AMARACUS pricing

Effective 28 November 2026. Prices are in US dollars and exclude taxes unless stated. The amounts below
are the ones in the code (`apps/api/src/lib/billing-plans.ts`); if the two ever differ, the price you were
shown when you bought governs your purchase.

## Self-hosted AMARACUS

| | |
| --- | --- |
| First 10,000 successful billable operations | Free, once, for the lifetime of your corporate group |
| Operation 10,001 onwards | **USD 0.15 per 1,000 operations** (USD 150 per million) |
| Team licence | **USD 1,200 a year** (INR 99,000 + GST in India): 10,000,000 operations a year and email support |
| How you pay | Prepaid licence keys, each covering a number of operations you choose, or the yearly Team licence |
| Who pays | Everyone above the allowance: individuals, students, startups, companies, banks, enterprises |

- The allowance is **lifetime and cumulative**, not monthly. It never renews.
- **One allowance per corporate group**: all employees, subsidiaries, affiliates, projects, environments,
  installations and servers share it. Reinstalling or adding servers does not reset it.
- The per-operation rate is the same as the AMARACUS Cloud Pay As You Go rate.
- What counts as a billable operation is defined in section 5 of
  [AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md). Failed operations,
  health checks, console use and idempotent retries are not counted.
- To buy a licence key or a Team licence, write to **legal@amaracus.tech** with your corporate group's
  legal name and the number of operations. Price = operations ÷ 1,000 × USD 0.15.
- Your installation verifies the key offline. Nothing is reported to AMARACUS.

## AMARACUS Cloud (hosted at amaracus.tech)

AMARACUS Cloud has four plans and **no free plan**. The self-hosted lifetime allowance does not apply to
Cloud, and self-hosted licence keys cannot be used there.

| Plan | Monthly | Yearly (two months free) | India (+ 18% GST) | Included operations per month | Members |
| --- | --- | --- | --- | --- | --- |
| Starter | USD 9 | USD 90 | INR 799 / month, INR 7,990 / year | 50,000 | 1 |
| Pro | USD 49 | USD 490 | INR 3,999 / month, INR 39,990 / year | 500,000 | 5 |
| Business | USD 299 | USD 2,990 | INR 24,999 / month, INR 2,49,990 / year | 3,000,000 | 25 |
| Pay As You Go | no monthly fee | not offered | not offered | none: USD 0.15 per 1,000 operations, up to a spending cap you set | 100 |

**Overage instead of a hard stop.** On Starter, Pro and Business, operations past the monthly allowance keep
working at **USD 0.12 per 1,000** (INR 10 per 1,000 + GST in India), up to a cap of one month's plan price
(USD 9, 49 or 299). At the cap, operations stop until the next month. You can lower the cap, or switch
overage off so operations stop at the allowance, in **Console → Billing**. Yearly plans reset the allowance
every month; on yearly plans paid in INR, overage is not available and operations stop at the allowance.

**Earlier plans.** Subscriptions bought before 28 November 2026 (Starter USD 2 / 15,000, Pro USD 20 /
150,000, Business USD 99 / 1,000,000) keep their price and allowance for as long as they stay active.

## Enterprise and services

| | Price | What you get |
| --- | --- | --- |
| Enterprise (self-hosted or Cloud) | from **USD 6,000 a year** | SLA, priority security patches, upgrade help, answers to your security questionnaires |
| PQC readiness assessment | **USD 2,500** one-off (INR 1.5 lakh + GST in India) | CBOM scan, migration plan and a call with us; credited in full toward a first year of Enterprise |

Enterprise and the assessment are invoiced directly. Write to **legal@amaracus.tech**.

Cloud plan limits, features and terms are on [amaracus.tech/pricing](https://amaracus.tech/pricing) and in
the AMARACUS Cloud Terms of Service.
