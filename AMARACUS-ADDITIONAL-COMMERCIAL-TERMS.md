# AMARACUS Additional Commercial Terms

Version: 1.0.0
Effective date: 12 November 2026
Licensor: Amaracus Technologies (corporate registration pending), Bengaluru, Karnataka 560103, India ("AMARACUS", "we", "us")
Licensing contact: legal@amaracus.tech

These terms apply to **self-hosted AMARACUS**: the AMARACUS source code and anything built from it that you run on infrastructure you control. They apply **together with** the PolyForm Shield License 1.0.0 in the file `LICENSE`. They do not apply to AMARACUS Cloud (the hosted service at amaracus.tech), which has its own terms of service.

AMARACUS is **source-available** software. It is not "open source" as defined by the Open Source Initiative, and no OSI-approved licence applies to it.

---

## 1. How the two documents work together

1.1 **Two documents, one licence offer.** We offer the Software to you only on the combination of (a) the PolyForm Shield License 1.0.0 ("Shield"), reproduced without changes in `LICENSE`, and (b) these Additional Commercial Terms ("Terms"). Together they are the "Agreement". We do not offer the Software under Shield alone.

1.2 **Shield is not modified.** Nothing in these Terms changes the text of Shield. These Terms are separate conditions and promises that you accept in addition to Shield, as Shield's "Acceptance" section allows a licensor to require: you get a licence only if you agree to all the conditions we attach to it.

1.3 **Conditions and promises.** Each obligation in sections 4 to 9 is both (a) a condition of every licence we grant you for the Software, and (b) a contractual promise you make to us. If a court finds that an obligation cannot operate as a licence condition, it still binds you as a contractual promise, and the reverse.

1.4 **If they conflict.** Where Shield permits something that these Terms restrict or make subject to payment, these Terms apply. Where these Terms are silent, Shield applies. Shield's Noncompete, Notices, Patent Defense, Fair Use and No Liability sections always apply in full.

1.5 **Rights the law gives you.** These Terms do not limit fair use, fair dealing or other rights that the law gives you and that cannot be waived by agreement.

## 2. Definitions

**Software** means AMARACUS as we make it available under the Agreement, in source or built form, including every version, and every copy, part, modification, port, translation into another programming language and fork of it, whoever made it.

**You** means the individual or legal entity accepting the Agreement. If you accept for a company or other organization, "you" means that organization, and you confirm you have authority to bind it.

**Affiliate** and **control** have the meanings given in Shield's Definitions.

**Corporate Group** means you together with all your Affiliates from time to time, treated as one licensee. An individual who is not acting for an organization is their own Corporate Group.

**Installation** means any running instance, deployment, environment, server, cluster, container, project or tenant of the Software operated by or for any member of your Corporate Group, including test, staging, disaster-recovery and development instances, and including instances run for you by a contractor or cloud provider.

**Billable Operation** is defined in section 5.

**Lifetime Allowance** means 1,000 Billable Operations.

**Usage Ledger** means the append-only, hash-chained record of Billable Operations that the Software keeps in your own database (`usage_ledger_entry`), or an equivalent complete and accurate record if you run a modified version.

**Licence Key** means a signed key issued by us that records a number of paid Billable Operations.

**AMARACUS Cloud** means the hosted service we operate at amaracus.tech.

## 3. Acceptance

3.1 **How you accept.** You accept the Agreement by doing any of the following: (a) clicking the accept button on the activation screen of a self-hosted Installation; (b) installing, building, running or otherwise using the Software; or (c) distributing the Software or anything based on it.

3.2 **Activation screen.** The unmodified Software does not run cryptographic operations until a signed-in person has been shown both documents and has accepted them. The Software stores, in your own database only, who accepted, when, for which licensee, and the SHA-256 hashes of the exact texts accepted. It does not send this record to us.

3.3 **Removing the screen does not remove the Agreement.** If you obtain or use the Software in a way that skips the activation screen (for example by modifying the code or calling it as a library), you still accept the Agreement under 3.1(b).

3.4 **If you do not agree.** If you do not accept the whole Agreement, you have no licence and must not use, copy, modify or distribute the Software.

3.5 **New versions of these Terms.** A later version of these Terms applies to a version of the Software only if it ships with that version. If an upgrade ships changed Terms, the Software asks for acceptance again. You may keep using an earlier version of the Software under the Terms that shipped with it.

## 4. Lifetime Allowance and payment

4.1 **1,000 operations free, once, for life.** The first 1,000 successful Billable Operations performed by your Corporate Group are free of charge. The allowance is cumulative and lifetime. It is not monthly and it never renews.

4.2 **The same for everyone.** The Lifetime Allowance is the same for individuals, students, startups, companies, banks, public bodies and enterprises. There is no separate non-commercial, academic or evaluation allowance.

4.3 **One allowance per Corporate Group.** Your whole Corporate Group shares a single Lifetime Allowance. All employees, contractors, subsidiaries, Affiliates, business units, projects, environments, Installations, servers and users count towards it together.

4.4 **No resets.** The following do not create a new Lifetime Allowance or reduce the count: reinstalling; deleting or resetting a database; creating additional Installations, projects, organizations or accounts; using a fork or a modified version; restoring from a backup; moving to different infrastructure; or spreading use across Affiliates, shell entities or individuals acting for the same organization.

4.5 **Changes to your group.** If Corporate Groups combine (merger, acquisition or similar), their Billable Operations are added together from the date of the combination, and the combined group has one Lifetime Allowance. An entity that leaves a Corporate Group does not receive a new Lifetime Allowance for use it made or benefited from as part of that group.

4.6 **Payment from operation 1,001.** Every Billable Operation after the first 1,000 must be paid for at the price in `AMARACUS-PRICING.md` as it stood when you bought the Licence Key that covers it. At the date of these Terms the price is **USD 0.15 per 1,000 Billable Operations**, the same as the AMARACUS Cloud Pay As You Go rate.

4.7 **How you pay: Licence Keys.** You pay in advance by buying Licence Keys from us. Each Licence Key covers a stated number of Billable Operations. A Licence Key belongs to the Corporate Group it was issued to. The operations it covers may be used once: entering the same Licence Key in several Installations does not multiply them, and the total across all your Installations must not exceed what you have bought.

4.8 **The built-in limit.** The unmodified Software stops performing new protective operations (for example encrypt, sign, wrap, generate key) when an Installation's Usage Ledger reaches the Lifetime Allowance plus the operations of the Licence Keys entered in it. This limit is disclosed here and in `README.md`; it works entirely on your own systems and contacts no one. Because operations run concurrently, an Installation can go a few operations past its limit before it stops; those operations are Billable Operations like any other. The limit counts per Installation. Your legal obligation is per Corporate Group (4.3, 4.7): where the limit in an Installation is higher than what your Corporate Group is entitled to, the obligation governs, not the limit.

4.9 **No refunds for unused operations**, except where the law requires one or we agree otherwise in writing. Paid operations do not expire.

4.10 **Taxes.** Prices exclude taxes. You pay any sales, value-added, goods and services, withholding or similar taxes that apply to your purchase, other than taxes on our income.

4.11 **Price changes.** We may change the price for future purchases by publishing a new `AMARACUS-PRICING.md`. A change does not affect Licence Keys you have already bought.

4.12 **Not transferable to AMARACUS Cloud.** The Lifetime Allowance and Licence Keys apply to self-hosted use only. AMARACUS Cloud has no free plan; its plans are Starter, Pro, Business and Pay As You Go.

## 5. What counts as a Billable Operation

5.1 **Definition.** A Billable Operation is one successful execution, by the Software, of a cryptographic function on behalf of a caller. In the unmodified Software these are exactly the operations it writes to the Usage Ledger. They include:

| Operation | Counted as |
| --- | --- |
| Encrypt, decrypt | 1 each |
| Wrap key, unwrap key (including envelope data-key wrapping requested as its own call) | 1 each |
| Sign, verify (classical and post-quantum) | 1 each |
| Hash, HMAC, HMAC verify | 1 each |
| Random-bytes generation | 1 per call |
| Key agreement, KEM key generation, encapsulate, decapsulate (classical, post-quantum, hybrid) | 1 each |
| Managed key generation (creating a key) | 1 per key |
| Key-pair generation | 1 per call |
| Certificate issuance, certificate renewal, signing a certificate request | 1 per certificate |
| Creating a certificate authority | 1 per authority |
| Operations with a customer-held (BYOK) key: encrypt, decrypt, sign, verify | 1 each |
| Advanced schemes: FHE key generation, encrypt, evaluate, decrypt; ZK prove, verify; MPC execute; threshold key generation, threshold sign | 1 each |

5.2 **Not counted.** The following are not Billable Operations: an operation that fails or is rejected; health and readiness checks; signing in, visiting the console and other administration; reading, listing or searching keys, policies, logs and other records; changing a key's state (enable, disable, archive, revoke, destroy); and a repeated request that carries the same idempotency key and the same request body as one already counted (a genuine retry). Reusing an idempotency key for a different request does not avoid the count.

5.3 **Key rotation.** Rotating a managed key is not itself counted in this version of the Software. Operations performed with the new key version are counted like any other.

5.4 **Batches.** If a single request performs several cryptographic operations (several items, several recipients or several keys), each one is a Billable Operation. This version of the Software has no batch endpoint; the rule applies to any later version or modification that adds one.

5.5 **Internal steps.** Cryptographic steps the Software performs inside a single counted operation (for example generating and wrapping a data key while encrypting) are not counted again.

5.6 **Decrypt and verify are counted but never blocked.** Decryption, unwrapping, decapsulation and verification are Billable Operations. The unmodified Software never refuses them for licensing reasons (section 8.3), so they may take your count above what you have paid for. You must then buy a Licence Key covering them within 32 days.

5.7 **Modified versions.** If you run a modified version, a fork, or use parts of the Software as a library, every successful operation of a kind listed in 5.1 is a Billable Operation whether or not your version records it, and you must keep an equivalent complete and accurate record.

## 6. Usage records

6.1 **Keep accurate records.** You must keep a complete and accurate record of the Billable Operations of your whole Corporate Group. For the unmodified Software, the Usage Ledger of each Installation is that record.

6.2 **Do not tamper.** You must not alter, delete, truncate, reset, roll back, disable or bypass the Usage Ledger or the limit in 4.8, or do anything intended to make the count lower than the true count. Removing an Installation does not remove the operations it performed from your Corporate Group's count.

6.3 **Retention.** You must keep the Usage Ledger of every Installation, including Installations you have shut down, and any equivalent records, for at least **7 years** after the operations they record. Export the ledger before you destroy an Installation's database.

6.4 **Limits of a local ledger.** The Usage Ledger is tamper-evident, not tamper-proof. A person who controls a server and its database can run modified code or rebuild records. That is why the obligations in this section and the audit right in section 7 exist: the legal duty to count and pay accurately does not depend on the ledger being impossible to change.

6.5 **No routine reports.** You do not have to send us usage reports on a schedule. You must give us a statement when we ask under 7.1.

## 7. Usage statements and audit

7.1 **Statement on request.** Not more than once in any 12 months, and at any time if we have reasonable grounds to believe usage is under-counted, we may ask you in writing for a usage statement. Within 30 days you must send us, signed by an authorized officer: (a) the total Billable Operations of your Corporate Group to date; (b) a list of your Installations, with the total and the latest ledger hash for each; (c) the Licence Keys you hold; and (d) confirmation that the records are complete and accurate.

7.2 **Independent audit.** If we have reasonable grounds to believe that a statement is inaccurate or that usage is under-counted, we may appoint an independent auditor to verify your Billable Operations. The audit:

- needs at least 30 days' written notice;
- happens not more than once in any 12 months, unless a previous audit found under-counting;
- takes place in business hours and in a way that does not unreasonably interfere with your operations;
- is limited to what is needed to verify Billable Operations: Usage Ledgers and their verification results, the list of Installations, deployment and version records, and Licence Keys;
- complies with your reasonable security, site-access and regulatory requirements.

7.3 **Confidentiality safeguards.** The auditor must be independent of both parties and must sign a confidentiality agreement with you before starting. The auditor may tell us only (a) the number of Billable Operations found, (b) the difference from what was paid for, and (c) the facts needed to explain that difference. The auditor must not give us, and we will not ask for or receive: your cryptographic keys or key material, plaintext, ciphertext, customer or personal data, the content of your audit logs, your source code modifications, or business information unrelated to the count. If you are a regulated entity, you may require the auditor to be acceptable to your regulator, and you may redact anything the law forbids you to disclose, as long as the count can still be verified.

7.4 **Who pays for the audit.** We pay for the audit. If it finds that you under-paid by more than 5% of what was due for the audited period, you reimburse the reasonable cost of the audit.

7.5 **Cooperation.** You must cooperate reasonably with a statement request and an audit, and make sure your Affiliates do.

## 8. What we will not do

8.1 **No mandatory telemetry.** The Software does not need to contact us to work. It contains no code that reports your usage, logs, keys, data, configuration or identity to us or to anyone else. Licence Keys are verified offline.

8.2 **No hidden tracking and no secret outbound requests.** We will not add undisclosed tracking, undisclosed outbound network requests, backdoors or spyware to the Software. The Software makes network requests only to services you configure (for example your database, your email provider, your Azure Key Vault or your webhook endpoints). Because the source is available, you can check this.

8.3 **No secret kill switches; your data stays readable.** The Software contains no remote kill switch and no mechanism by which we can disable your Installation. The only licensing limits in the Software are the activation screen (3.2) and the built-in limit (4.8), both disclosed here. Neither of them ever blocks decryption, unwrapping, decapsulation or verification. You keep the ability to decrypt and verify data you protected earlier even if you have not paid, your licence has ended, or we stop maintaining or distributing the Software.

8.4 **No mandatory log collection.** We do not collect your cryptographic or audit logs. We receive usage information only when you send a statement under 7.1 or an auditor reports under 7.3.

8.5 **Keys stay with you.** Your key material stays in your own database, your own key vault or your own HSM. We have no access to it.

## 9. Under-payment and misreporting

9.1 **Paying what is owed.** If a statement or audit establishes that your Corporate Group performed more Billable Operations than it paid for, you must pay for the difference within 30 days of the invoice, at the price in force when the operations were performed.

9.2 **Interest.** Amounts not paid when due carry simple interest at 1% per month, or the highest rate the law allows if that is lower, from the due date until paid.

9.3 **Material misreporting.** "Material misreporting" means (a) under-payment of more than 10% of what was due for the period examined, or (b) any deliberate alteration, deletion, reset or bypass of usage records or of the built-in limit in order to under-count. For material misreporting, in addition to 9.1 and 9.2: you pay an additional charge equal to 50% of the under-paid amount, as a genuine pre-estimate of our cost of detection and recovery; you reimburse the reasonable cost of the audit; and we may ask for statements every 6 months for the following 3 years.

9.4 **Ending the licence.** A failure to pay amounts due, or material misreporting, is a violation of the Agreement. Shield's "Violations" section applies: if this is the first time you are notified in writing, your licences continue if you pay what is owed and come into full compliance within 32 days of the notice. Otherwise all your licences end.

9.5 **After the licence ends.** If your licences end, you must stop using the Software for new operations and stop distributing it. You may continue to use it for as long as you reasonably need, and only as far as needed, to decrypt, unwrap and verify data protected before the licences ended and to move that data elsewhere. Amounts you owe remain payable.

9.6 **Other remedies.** Sections 9.1 to 9.5 do not limit any other remedy the law gives us, including for copyright infringement by use outside the licence.

## 10. Competition

10.1 Shield's Noncompete section applies in full: you may not use the Software to provide any product that competes with the Software or with any product we or our Affiliates provide using the Software.

10.2 `AMARACUS-COMPETITION-POLICY.md` explains, with examples, how we read that restriction. It is an explanation, not an extra restriction: it does not prohibit anything that Shield permits.

10.3 Nothing in the Agreement stops anyone from independently developing any product, including a competing one, without using or copying the Software.

## 11. Distribution, forks and downstream recipients

11.1 **You may distribute** the Software and your modifications as Shield permits, for permitted purposes.

11.2 **Pass on both documents.** Anyone who receives any part of the Software from you must also receive `LICENSE`, this file, `NOTICE` and every line beginning with `Required Notice:` that we provide with the Software. Shield's "Notices" section requires the `Required Notice:` lines to be passed on; ours state that the Software is offered only under the Agreement.

11.3 **No sublicensing.** As Shield provides, you cannot sublicense or transfer your licences. Everyone who receives the Software gets their licence directly from us, on the Agreement, and must accept it themselves. Receiving a copy from you gives them no right to your Lifetime Allowance or your Licence Keys.

11.4 **Forks and modifications.** A modified version or fork remains the Software. The Agreement, including payment for Billable Operations and the Noncompete, applies to it and to everyone who uses it. You must not remove or weaken the licence files, the `Required Notice:` lines, or (in a version you distribute to others) the activation screen and Usage Ledger, and you must not present a modified version as the official AMARACUS release.

11.5 **Each recipient has its own allowance.** A recipient that is not part of your Corporate Group has its own Lifetime Allowance and its own payment obligations to us.

11.6 **Trademarks.** The Agreement gives no right to use the AMARACUS name or logo, except to state accurately that your work is based on AMARACUS.

## 12. No obligation to maintain or support

12.1 The Software is provided "as is" and "as available", to the maximum extent the law permits.

12.2 AMARACUS and its maintainers are not obliged to: continue developing the Software; maintain or update the public repository; release new versions or security patches; fix bugs, vulnerabilities or compatibility issues; maintain compatibility with future operating systems, databases, cloud providers, APIs or dependencies; provide technical support, customer service or migration assistance; keep the repository, documentation, downloads or hosted resources available indefinitely; or continue operating AMARACUS Cloud or any associated service indefinitely.

12.3 We may suspend, discontinue, archive, transfer or permanently stop developing and maintaining the Software or the repository at any time.

12.4 You are responsible for: keeping your own copies and backups of the source code; maintaining your own deployment infrastructure; managing your own encryption keys and recovery procedures; applying security updates where available; maintaining compatibility with your infrastructure; and ensuring your own business continuity.

12.5 You should not assume that we will provide perpetual maintenance, updates, support, availability or continued development.

12.6 To the maximum extent the law permits, we disclaim liability arising solely from the discontinuation of development, repository maintenance, updates or support.

12.7 This section does not remove liability that cannot legally be excluded, does not override mandatory consumer protections, and does not remove obligations we have expressly agreed to in a separate commercial contract or service agreement.

12.8 If we stop issuing Licence Keys and name no successor who does, then for as long as that continues you may keep using the versions of the Software you already have without buying further Licence Keys, and you may remove the built-in limit in 4.8 from your own Installations. Your other obligations, including the Noncompete, continue.

## 13. Liability

13.1 Shield's "No Liability" section applies to the Software.

13.2 To the maximum extent the law permits, our total liability arising out of the Agreement is limited to the amounts you paid us for Licence Keys in the 12 months before the claim arose.

13.3 Nothing in the Agreement excludes liability that cannot be excluded by law.

## 14. General

14.1 **Governing law.** The Agreement is governed by the laws of India, without regard to conflict-of-law rules.

14.2 **Disputes.** The parties will first try in good faith to resolve a dispute within 30 days of written notice. A dispute not resolved in that time will be finally resolved by arbitration under the Arbitration and Conciliation Act, 1996, by a sole arbitrator. The seat and venue is Bengaluru, Karnataka, India, and the language is English. Subject to that, the courts at Bengaluru, Karnataka have exclusive jurisdiction. Either party may seek urgent injunctive relief in any competent court to protect its intellectual property or confidential information.

14.3 **Consumers.** If you are a consumer, nothing in the Agreement removes rights that consumer law gives you and that cannot be waived.

14.4 **Severability.** If a provision is held unenforceable, it is to be enforced as far as the law allows and the rest of the Agreement continues.

14.5 **Assignment.** We may assign the Agreement to a successor to our business or to the Software. Shield's "Sales of Business" section applies. You may not assign it without our written consent, except to a successor to substantially all of your business, who takes on your Corporate Group's count and obligations.

14.6 **Separate written agreements.** If you have a signed commercial agreement with us that covers self-hosted use (for example an enterprise licence with different pricing or reporting), that agreement applies where it differs from these Terms.

14.7 **Notices.** Send notices to us at legal@amaracus.tech. We send notices to you at the address of the person who accepted the Agreement, or another address you give us in writing.

14.8 **Entire agreement.** The Agreement (Shield and these Terms), together with `AMARACUS-PRICING.md` for prices, is the whole agreement between you and us about self-hosted use of the Software.

14.9 **No legal review is claimed.** We publish these Terms in good faith. We make no statement that they have been reviewed or validated by a court, a regulator or independent counsel in any country. `docs/LICENSING.md` describes openly the points on which the combination of Shield and these Terms is untested.
