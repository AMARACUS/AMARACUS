import { pageMetadata } from '@/lib/seo';

export const metadata = pageMetadata({
  title: 'Create an Account',
  description: 'Create an AMARACUS account, then choose a plan: from $2 a month for 15,000 operations, or pay as you go.',
  path: '/signup/',
});

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
