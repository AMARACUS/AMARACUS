import { pageMetadata } from '@/lib/seo';

export const metadata = pageMetadata({
  title: 'Sign In',
  description: 'Sign in to the AMARACUS console to manage keys, API credentials and policies.',
  path: '/login/',
});

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
