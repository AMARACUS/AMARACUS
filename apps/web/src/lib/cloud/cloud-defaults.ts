/**
 * Defaults for a self-hosted AMARACUS installation. This file replaces src/lib/cloud/cloud-defaults.ts in the
 * public source tree. Set NEXT_PUBLIC_API_URL and NEXT_PUBLIC_APP_URL at build time to your own addresses.
 */
export const cloudDefaults = {
  /** API base URL used when NEXT_PUBLIC_API_URL is not set at build time. */
  apiUrl: 'http://localhost:4000',
  /** Public site URL used when NEXT_PUBLIC_APP_URL is not set at build time. */
  siteUrl: 'http://localhost:3000',
  /** Where to buy a licence key from AMARACUS. */
  licensingContactEmail: 'legal@amaracus.tech',
  /** The web app asks the API for its edition at runtime. */
  probeEdition: true,
  /** There is no AMARACUS Cloud marketing or legal site in a self-hosted build. */
  hasCloudSite: false,
} as const;
