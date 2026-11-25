import { pageMetadata } from '@/lib/seo';

export const metadata = pageMetadata({
  title: 'Connect an App',
  description: 'Approve a connection between your AMARACUS organization and an AI assistant or coding agent.',
  path: '/connect/',
  noindex: true,
});

export default function Layout({ children }: { children: React.ReactNode }) {
  return children;
}
