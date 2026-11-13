# How AMARACUS's two licence documents fit together

AMARACUS is offered under two documents at once:

1. [`LICENSE`](../LICENSE): the **PolyForm Shield License 1.0.0**, the official text, unmodified
   (SHA-256 `56328093d57c87dcf2811ddcc824caf2723a07ffc332e6fbe4f9f108a2893a91` with LF line endings).
2. [`AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md`](../AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md): payment beyond
   the 1,000-operation lifetime allowance, records, audit, no-telemetry commitments and the rest.

This page explains the structure and states openly which points are untested. Nothing here claims that a court,
regulator or independent lawyer has confirmed the arrangement.

## The structure

- **One offer, two documents.** AMARACUS does not offer the software under Shield alone. The offer is Shield
  plus the Additional Terms (terms 1.1). Every copy carries both, and `NOTICE` carries `Required Notice:` lines
  that say so.
- **Shield is not edited.** It keeps its name and text. The extra obligations are in a separate, separately
  named document, so nobody can mistake the combination for plain Shield.
- **Conditions and promises.** Each extra obligation is both a condition of the licence and a contractual
  promise (terms 1.3), so it can be enforced either through copyright (use outside the licence) or through
  contract (breach of a promise).
- **Click-to-accept.** The software will not run cryptographic operations until a signed-in administrator has
  been shown both texts and has accepted them; the acceptance and the hash of each text are stored. Use or
  distribution also counts as acceptance (terms 3.1).

## The points checked, and what remains uncertain

### 1. Can a payment obligation sit alongside Shield's grant?

Shield grants a copyright licence "for any permitted purpose", and its Noncompete makes every purpose
permitted except competing. Read alone, Shield needs no payment.

The structure relies on Shield's own **Acceptance** section ("you must agree to them as both strict
obligations and conditions to all your licenses") and on the general principle that a licensor may attach
further conditions to its own offer. Terms 1.4 says the Additional Terms prevail where Shield is more
generous.

**Uncertain:** someone could argue that a licence called "PolyForm Shield" was granted on Shield's terms
alone, and that the Additional Terms restrict a grant that Shield made unconditionally. The answer will depend
on how clearly a particular recipient was told about the Additional Terms and whether they accepted them.
This is the main risk in the arrangement.

**The cleaner alternative, if that risk matters to you:** publish one licence under AMARACUS's own name (for
example "AMARACUS Source-Available License 1.0") whose text reproduces Shield's terms with attribution and adds
the commercial terms. That removes any argument that two documents conflict. It would no longer be "PolyForm
Shield", so it could not use that name. The PolyForm Project publishes guidance on using and adapting its
licences on polyformproject.org; read it before choosing.

### 2. How are original users and downstream recipients bound?

- Shield forbids sublicensing ("No Other Rights"), so every recipient, including someone who got a fork from a
  third party, receives their licence **directly from AMARACUS**. That is helpful: AMARACUS can rely on its own
  terms with every user, not only with first-hand downloaders.
- Shield's **Notices** section obliges every distributor to pass on the licence and every `Required Notice:`
  line. AMARACUS's `Required Notice:` lines name the Additional Terms, so a distributor who strips them breaches
  Shield.
- **Uncertain:** a downstream user who never sees the activation screen (because a fork removed it) is bound
  only through "use counts as acceptance" (terms 3.1(b), 3.3). How far that kind of acceptance binds depends on
  the country and on whether the notices were present.

### 3. How are modified forks covered?

Terms 2 defines the Software to include every modification, port, translation and fork, and 11.4 forbids
removing the licence files, notices, activation screen or ledger in a version distributed to others. Shield's
Noncompete already covers competing products in other languages and interfaces. **Uncertain:** whether code
rewritten so thoroughly that little original expression remains is still "based on" AMARACUS is a question of
copyright fact in each case; independent development is expressly allowed (terms 10.3).

### 4. Does redistribution need a new acceptance?

Yes, in the sense that each recipient's licence comes from AMARACUS and needs their own acceptance (terms
11.3). The distributor does not accept for them. Recipients outside the distributor's corporate group get
their own lifetime allowance and their own obligations (11.5).

### 5. Termination and audit

- **Termination** follows Shield's "Violations" section: 32 days to cure after a first written notice, then
  the licence ends (terms 9.4). After termination, decrypting and verifying existing data stays allowed for as
  long as reasonably needed (9.5), which matches the promise that data never becomes unreadable.
- **Audit** is limited: on reasonable grounds, at most once a year (unless under-counting was found), 30 days'
  notice, an independent auditor under a confidentiality agreement with the customer, and no access to keys,
  plaintext, personal data or log content (terms 7).
- **Uncertain:** the additional 50% charge for material misreporting (terms 9.3). Under the Indian Contract
  Act, 1872, section 74, a court awards reasonable compensation up to a stated amount rather than enforcing a
  penalty as written, so the charge may be reduced. Other countries treat penalty clauses differently.

### 6. The built-in limit is not the legal rule

The software counts per installation; the licence counts per corporate group. The software cannot see other
installations and makes no network request, by design. The legal rule therefore depends on the customer's own
records, the usage-statement request and the audit right, not on the software. The terms say so (4.8, 6.4).

### 7. Other points

- **Client SDKs and CLI** are Apache-2.0. Versions already published under Apache-2.0 stay available under it
  regardless of later changes. Using an SDK to call a self-hosted AMARACUS does not change what the server's
  operations cost.
- **Contributions** come in under [CLA.md](../CLA.md), which gives AMARACUS the right to use them in the paid
  hosted service and under any licence. Without it, AMARACUS would hold a contributor's code only under
  whatever licence the contributor chose, which might not allow commercial hosting.
- **Consumers**: mandatory consumer law applies regardless (terms 14.3).
- **Earlier copies**: if any version of this code was ever published under a different licence, copies
  obtained under that licence keep it.

## Summary

| Question | Status |
| --- | --- |
| Shield text unmodified and correctly named | Yes |
| Extra obligations in a separate, clearly named document | Yes |
| Every copy carries both, through `Required Notice:` lines | Yes |
| Click-to-accept in the software, acceptance recorded locally | Yes |
| Payment obligation compatible with Shield's grant | Arguable, untested (point 1) |
| Binding on users who never see the activation screen | Depends on the country (point 2) |
| Misreporting charge enforceable as written | Uncertain (point 5) |
| Reviewed by a court, regulator or independent lawyer | No |
