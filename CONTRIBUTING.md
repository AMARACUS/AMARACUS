# Contributing to AMARACUS

Thank you for helping. AMARACUS is source-available: the code is public, and contributions are welcome under
the conditions below.

## Before you start

- **Contributor Licence Agreement.** Every pull request needs the contributor's acceptance of [CLA.md](CLA.md).
  It gives AMARACUS the rights to ship your contribution both in this repository and in AMARACUS Cloud. You
  keep your copyright. Tick the CLA box in the pull request template (or comment "I have read the CLA and I
  accept it"). If you contribute for an employer, make sure you are allowed to.
- **Licences.** Your contribution is distributed under [LICENSE](LICENSE) (PolyForm Shield 1.0.0) together
  with the [AMARACUS Additional Commercial Terms](AMARACUS-ADDITIONAL-COMMERCIAL-TERMS.md); contributions to
  `packages/sdk-ts`, `packages/sdk-py` and `packages/cli` under Apache-2.0. Do not submit code you copied from
  elsewhere unless its licence allows it, and say where it came from.
- **Security issues** go to security@amaracus.tech, not to a pull request (see [SECURITY.md](SECURITY.md)).
- For a large change, open an issue first to agree the approach.

## Making a change

1. Fork, then create a branch.
2. `pnpm install --frozen-lockfile`, build the packages (see [README.md](README.md)), and make your change.
3. Add or update tests. Run `cd apps/api && NODE_ENV=test npx jest --ci`, `pnpm --filter api exec tsc --noEmit`
   and `pnpm --filter web typecheck`.
4. Do not commit secrets, `.env` files, personal data, build output or `node_modules`.
5. Do not add telemetry, tracking, outbound calls to AMARACUS or a remote kill switch, and do not weaken the
   activation screen, the usage ledger or the licence notices. Such pull requests will be closed.
6. Open a pull request into `main` and fill in the template.

## What happens after you open a pull request

1. A maintainer reviews it. CI must pass.
2. When it is approved and merged here, a maintainer brings the same commit into AMARACUS's private
   repository through a separate reviewed pull request, where AMARACUS Cloud's own tests run. Only after that
   review is it deployed to amaracus.tech. Nothing reaches the hosted service automatically.
3. Maintainers may decline or change a contribution, and are not obliged to merge or maintain it.

## Code of conduct

Everyone taking part follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
