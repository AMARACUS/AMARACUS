import { cloudDefaults } from './cloud/cloud-defaults';

/**
 * The one API base URL for the web app.
 *
 * NEXT_PUBLIC_API_URL is baked in at build time (for local development set it to
 * http://localhost:4000 in apps/web/.env.local). Without it the default in lib/cloud/cloud-defaults.ts is used
 * (the production API in the AMARACUS Cloud tree, http://localhost:4000 in the self-hosted tree).
 * Never a relative path: Cloudflare Pages does not proxy /v1 or /api/v1 to the API, so
 * same-origin requests would 404.
 */
export const API_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || cloudDefaults.apiUrl).replace(/\/+$/, '');

/** Absolute URL for an API path, e.g. apiUrl('/v1/keys'). */
export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}
