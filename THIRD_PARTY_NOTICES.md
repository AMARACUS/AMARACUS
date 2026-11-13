# Third-Party Notices

AMARACUS is distributed as source code. It depends on open-source packages from the npm registry. These packages are not included in this repository. They are installed by `pnpm install` from the lockfile (`pnpm-lock.yaml`) and stay under their own licences. A container image built from this repository will contain those packages and must keep their licence files (each package ships its own LICENSE and, where applicable, NOTICE file in `node_modules`).

This file lists the direct dependencies declared in the workspace `package.json` files, summarises the licences of all resolved dependencies, and records the packages whose licences ask for a specific notice. Licence identifiers are read from each package `package.json` `license` field and, for unusual entries, checked against the package own LICENSE file. The data was generated from the installed tree and `pnpm-lock.yaml` on 2026-11-12. Re-run the scan whenever the lockfile changes.

## 1. Direct dependencies

Workspaces: root, `apps/api`, `apps/web`, `packages/*`, `examples/*`. Type is prod (dependencies and optionalDependencies) or dev (devDependencies). Internal workspace packages are omitted.

| Package | Version | Licence | Type | Used by | URL |
|---|---|---|---|---|---|
| @ai-sdk/anthropic | 4.0.82 | Apache-2.0 | prod | root | https://ai-sdk.dev/docs |
| @ai-sdk/openai | 4.0.96 | Apache-2.0 | prod | root | https://ai-sdk.dev/docs |
| @azure/identity | 4.14.0 | MIT | prod | packages/crypto-core | https://github.com/Azure/azure-sdk-for-js/tree/main/sdk/identity/identity/README.md |
| @azure/keyvault-keys | 4.10.2 | MIT | prod | packages/crypto-core | https://github.com/Azure/azure-sdk-for-js/tree/main/sdk/keyvault/keyvault-keys/README.md |
| @composio/core | 0.25.0 | ISC | prod | root | https://github.com/ComposioHQ/composio/tree/next/ts/packages/core#readme |
| @noble/curves | 2.4.0 | MIT | prod | packages/crypto-core | https://paulmillr.com/noble/ |
| @noble/post-quantum | 0.7.1 | MIT | prod | apps/api, packages/crypto-core | https://paulmillr.com/noble/ |
| @peculiar/x509 | 2.1.0 | MIT | prod | apps/api, packages/crypto-core | https://github.com/PeculiarVentures/x509#readme |
| @playwright/test | 1.64.1 | Apache-2.0 | dev | root | https://playwright.dev |
| @prisma/client | 5.22.0 | Apache-2.0 | prod | packages/database | https://www.prisma.io |
| @trigger.dev/build | 4.7.4 | MIT | prod | root | https://github.com/triggerdotdev/trigger.dev |
| @trigger.dev/react-hooks | 4.7.4 | MIT | prod | apps/web | https://github.com/triggerdotdev/trigger.dev |
| @trigger.dev/sdk | 4.7.4 | MIT | prod | apps/web, root | https://github.com/triggerdotdev/trigger.dev |
| @types/cookie-parser | 1.4.10 | MIT | dev | apps/api | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/cookie-parser |
| @types/cors | 2.8.19 | MIT | dev | apps/api | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/cors |
| @types/express | 4.17.25 | MIT | dev | apps/api, examples/express-adapter | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/express |
| @types/jest | 30.0.0 | MIT | dev | apps/api | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/jest |
| @types/multer | 2.3.0 | MIT | dev | apps/api | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/multer |
| @types/node | 20.19.43 | MIT | dev | apps/web, examples/express-adapter, examples/nextjs-integration, packages/crypto-core, root | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/node |
| @types/node | 22.20.3 | MIT | dev | apps/api, examples/basic-node, packages/cli, packages/sdk-ts | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/node |
| @types/nodemailer | 8.0.2 | MIT | dev | apps/api | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/nodemailer |
| @types/react | 18.3.31 | MIT | dev | apps/web, examples/nextjs-integration | https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/react |
| ai | 7.0.143 | Apache-2.0 | prod | root | https://ai-sdk.dev/docs |
| autoprefixer | 10.6.1 | MIT | dev | apps/web | https://github.com/postcss/autoprefixer |
| bla-agents | 2.1.0 | MIT | dev | apps/web | https://bla.tools |
| clsx | 2.1.1 | MIT | prod | apps/web | https://github.com/lukeed/clsx |
| composio | 1.0.0 | MIT | prod | root | https://www.npmjs.com/package/composio |
| cookie-parser | 1.4.7 | MIT | prod | apps/api | https://github.com/expressjs/cookie-parser |
| cors | 2.8.6 | MIT | prod | apps/api | https://github.com/expressjs/cors |
| dotenv | 16.6.1 | BSD-2-Clause | prod | apps/api | https://github.com/motdotla/dotenv#readme |
| esbuild | 0.28.2 | MIT | dev | packages/crypto-core | https://github.com/evanw/esbuild |
| eslint | 8.57.0 | MIT | dev | apps/web | https://eslint.org |
| eslint-config-next | 14.2.35 | MIT | dev | apps/web | https://nextjs.org/docs/app/building-your-application/configuring/eslint#eslint-config |
| express | 4.22.3 | MIT | prod | apps/api, examples/express-adapter | http://expressjs.com/ |
| helmet | 7.2.0 | MIT | prod | apps/api | https://helmetjs.github.io/ |
| jest | 30.5.1 | MIT | dev | apps/api | https://jestjs.io/ |
| lucide-react | 1.46.0 | ISC | prod | apps/web | https://lucide.dev |
| multer | 2.5.0 | MIT | prod | apps/api | https://github.com/expressjs/multer |
| next | 14.2.35 | MIT | prod | apps/web, examples/nextjs-integration | https://nextjs.org |
| node-seal | 6.0.3 | MIT | prod | packages/crypto-core | https://s0l0ist.github.io/seal-sandbox/ |
| nodemailer | 10.1.0 | MIT-0 | prod | apps/api | https://nodemailer.com/ |
| postcss | 8.5.28 | MIT | dev | apps/web | https://postcss.org/ |
| prisma | 5.22.0 | Apache-2.0 | dev | apps/web, packages/database | https://www.prisma.io |
| razorpay | 2.9.8 | MIT | prod | apps/api | https://github.com/razorpay/razorpay-node |
| react | 18.3.1 | MIT | prod | apps/web, examples/nextjs-integration | https://reactjs.org/ |
| react-dom | 18.3.1 | MIT | prod | apps/web, examples/nextjs-integration | https://reactjs.org/ |
| reflect-metadata | 0.2.2 | Apache-2.0 | prod | apps/api, packages/crypto-core | http://rbuckton.github.io/reflect-metadata |
| shamir-secret-sharing | 0.0.4 | Apache-2.0 | prod | packages/crypto-core | https://github.com/privy-io/shamir-secret-sharing |
| tailwind-merge | 3.7.0 | MIT | prod | apps/web | https://github.com/dcastil/tailwind-merge |
| tailwindcss | 3.4.19 | MIT | dev | apps/web | https://tailwindcss.com |
| trigger.dev | 4.7.4 | MIT | dev | root | https://github.com/triggerdotdev/trigger.dev |
| ts-jest | 29.4.15 | MIT | dev | apps/api | https://kulshekhar.github.io/ts-jest |
| ts-node | 10.9.2 | MIT | dev | apps/api, examples/basic-node, examples/express-adapter | https://typestrong.org/ts-node |
| tsx | 4.23.15 | MIT | dev | root | https://tsx.hirok.io |
| typescript | 5.9.3 | Apache-2.0 | dev | apps/api, apps/web, examples/basic-node, examples/express-adapter, examples/nextjs-integration, packages/cli, packages/crypto-core, packages/database, packages/sdk-ts, packages/types, root | https://www.typescriptlang.org/ |
| uncrypto | 0.1.3 | MIT | dev | root | https://github.com/unjs/uncrypto |
| zod | 4.6.7 | MIT | prod | root | https://zod.dev |

## 2. All resolved packages by licence (direct and transitive)

1087 distinct name@version entries in the lockfile graph: 331 reachable from a production dependency of at least one workspace, 756 dev-only. Counts are per name@version.

| Licence (SPDX) | Total | Production | Dev-only |
|---|---|---|---|
| MIT | 805 | 249 | 556 |
| (not installed locally - platform binary) | 103 | 10 | 93 |
| Apache-2.0 | 65 | 49 | 16 |
| ISC | 55 | 9 | 46 |
| BSD-3-Clause | 19 | 5 | 14 |
| BSD-2-Clause | 13 | 1 | 12 |
| BlueOak-1.0.0 | 12 | 0 | 12 |
| (MIT OR CC0-1.0) | 3 | 0 | 3 |
| Unlicense | 2 | 2 | 0 |
| 0BSD | 2 | 2 | 0 |
| (AFL-2.1 OR BSD-3-Clause) | 1 | 1 | 0 |
| (Apache-2.0 AND BSD-3-Clause) | 1 | 1 | 0 |
| Public Domain | 1 | 0 | 1 |
| MIT-0 | 1 | 1 | 0 |
| CC-BY-4.0 | 1 | 1 | 0 |
| Python-2.0 | 1 | 0 | 1 |
| CC0-1.0 | 1 | 0 | 1 |
| MPL-2.0 | 1 | 0 | 1 |

Packages marked "not installed locally" are platform-specific binary packages (esbuild, Next.js SWC, rollup, fsevents, Parcel watcher, unrs-resolver, depot CLI, emnapi and similar) that pnpm skips on Windows. Their licences were not read from disk. The ones recognisable by name (esbuild, @next/swc, rollup, fsevents, @parcel/watcher) are published as MIT upstream, but that was not verified here. The licence of the @depot/cli-* binaries (dev-only, pulled in by trigger.dev) was not determined.

## 3. Packages that require a specific notice

No dependency in the lockfile declares GPL, AGPL, LGPL, SSPL, BUSL, Elastic, Commons Clause, CC-BY-NC or CC-BY-SA terms, and none is UNLICENSED or has a missing licence field.

| Package | Licence | Where it comes from | Required notice or obligation |
|---|---|---|---|
| axe-core 4.13.0 | MPL-2.0 | dev-only: apps/web, via eslint-config-next, eslint-plugin-jsx-a11y | MPL-2.0 is file-level copyleft. It is a lint-time tool and is not shipped to users. If it is redistributed unmodified (for example in an image that contains dev dependencies), keep its LICENSE and LICENSE-3RD-PARTY.txt and keep its source available (public on npm and GitHub). No effect on AMARACUS code. |
| caniuse-lite 1.0.30001810 | CC-BY-4.0 | build-time browser data: apps/web via next, apps/api dev via jest/babel | Attribution to the caniuse data authors; keep the licence file with the package. It is not part of the compiled web output. |
| @protobuf-ts/runtime 2.11.1 | Apache-2.0 AND BSD-3-Clause | production: @trigger.dev/sdk and @trigger.dev/build -> @trigger.dev/core -> @s2-dev/streamstore (root, apps/web) | Keep its LICENSE; if redistributed in binary form reproduce the BSD-3-Clause and Apache-2.0 notices. No NOTICE file. |
| json-schema 0.4.0 | AFL-2.1 OR BSD-3-Clause | production: @ai-sdk/provider (root, apps/web) | Dual licence. Elect BSD-3-Clause. Keep the Dojo Foundation copyright and licence notice. |
| import-in-the-middle 3.5.2 and 3.0.1 | Apache-2.0 | production: @trigger.dev/core -> @opentelemetry/instrumentation (root, apps/web) | Ships a NOTICE file. Apache-2.0 section 4(d) requires keeping it when redistributing. |
| playwright, playwright-core, @playwright/test 1.64.1 | Apache-2.0 | root devDependency (e2e tests) and auto-installed optional peer of next in apps/web | Ships a NOTICE file (Microsoft; contains code derived from Puppeteer, Apache-2.0). Keep it if redistributed. |
| argparse 2.0.1 | Python-2.0 | dev-only (apps/web, js-yaml chain) | PSF-style permissive licence. Keep the licence text if redistributed. |
| nodemailer 10.1.0 | MIT-0 | production: apps/api | None. MIT-0 has no attribution requirement. |
| Packages under MIT, ISC, 0BSD, BSD-2-Clause, BSD-3-Clause, Apache-2.0, BlueOak-1.0.0, Unlicense, CC0-1.0 | various | mixed | Standard attribution: keep each package copyright and licence text when redistributing in source or binary form. For Apache-2.0 packages also keep NOTICE files (only the packages named above ship one). BlueOak-1.0.0 (12 dev-only packages) asks that the licence and required notices are passed along. |
| Inter, Newsreader, JetBrains Mono fonts | SIL OFL 1.1 | apps/web, loaded with next/font/google at build time | Include the OFL licence text and copyright notices with any redistributed font files. |
| Google "G" sign-in mark | Google brand terms | apps/web login page | Trademark use under Google Identity branding guidelines; not covered by the AMARACUS licence. |

Full licence texts are not reproduced here. They are in each package own LICENSE file after `pnpm install`.
