import type { Metadata } from 'next';

import { cloudDefaults } from './cloud/cloud-defaults';

// AMARACUS Cloud keeps its fixed canonical host whatever the build environment says; a self-hosted
// build (no Cloud site) uses NEXT_PUBLIC_APP_URL.
export const SITE_URL = (
  cloudDefaults.hasCloudSite ? cloudDefaults.siteUrl : process.env.NEXT_PUBLIC_APP_URL || cloudDefaults.siteUrl
).replace(/\/+$/, '');
export const SITE_NAME = 'AMARACUS';

interface PageMetadataInput {
  /** Page title; the root layout appends " | AMARACUS". */
  title: string;
  description: string;
  /** Canonical path with a trailing slash (next.config uses trailingSlash: true). */
  path: string;
  /** Keep the page out of search results (account, admin and one-time-link pages). */
  noindex?: boolean;
}

export function pageMetadata({ title, description, path, noindex }: PageMetadataInput): Metadata {
  return {
    title,
    description,
    // A noindex page has no canonical (and must not inherit a parent's): it isn't meant to be indexed.
    alternates: noindex ? {} : { canonical: path },
    openGraph: {
      title: `${title} | ${SITE_NAME}`,
      description,
      url: path,
      siteName: SITE_NAME,
      type: 'website',
    },
    ...(noindex ? { robots: { index: false, follow: true } } : {}),
  };
}

export function absoluteUrl(path: string): string {
  return `${SITE_URL}${path}`;
}
