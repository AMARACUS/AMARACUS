import { pageMetadata } from '@/lib/seo';

export const metadata = pageMetadata({
  title: 'Choose a New Password',
  description: 'Set a new password for your AMARACUS account.',
  path: '/reset-password/',
  noindex: true,
});

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
