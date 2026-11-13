import { pageMetadata } from '@/lib/seo';

export const metadata = pageMetadata({
  title: 'Reset Your Password',
  description: 'Request a link to reset your AMARACUS password.',
  path: '/forgot-password/',
  noindex: true,
});

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
