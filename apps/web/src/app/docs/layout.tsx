import { pageMetadata } from '@/lib/seo';

export const metadata = pageMetadata({
  title: 'Encryption API Docs and Quickstart',
  description: 'Learn how AMARACUS works, then call the encryption, key management and post-quantum endpoints with copy-paste curl examples.',
  path: '/docs/',
});

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
