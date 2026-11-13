import { pageMetadata } from '@/lib/seo';
import { DashboardShell } from './dashboard-shell';

// The console is behind sign-in, so it stays out of search results.
export const metadata = pageMetadata({
  title: 'Console',
  description: 'The AMARACUS console for keys, API credentials, policies and audit logs.',
  path: '/dashboard/',
  noindex: true,
});

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return <DashboardShell>{children}</DashboardShell>;
}
