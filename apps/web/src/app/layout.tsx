import type { Metadata } from 'next';
import { Inter, Newsreader, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { AuthProvider } from '@/lib/auth-context';
import { EditionProvider } from '@/lib/edition';
import { CookieConsentProvider } from '@/lib/cookie-consent-context';
import { CookieConsentBanner } from '@/components/cookie-consent-banner';
import { SITE_URL } from '@/lib/seo';

// Self-hosted at build time: no request to Google Fonts when the page loads.
const inter = Inter({ subsets: ['latin'], variable: '--font-inter', display: 'swap' });
const newsreader = Newsreader({
  subsets: ['latin'],
  style: ['normal', 'italic'],
  axes: ['opsz'],
  variable: '--font-newsreader',
  display: 'swap',
});
const jetbrainsMono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono', display: 'swap' });

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: {
    default: 'AMARACUS (self-hosted)',
    template: '%s | AMARACUS',
  },
  description: 'Your own AMARACUS installation: encryption, key management and post-quantum cryptography through one REST API.',
  // A private installation should not appear in search results.
  robots: { index: false, follow: false },
  icons: { icon: '/icon.svg' },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${newsreader.variable} ${jetbrainsMono.variable}`}>
      <body className="min-h-screen bg-[#F8F7F4] text-[#1A1A1A] antialiased">
        <EditionProvider>
          <AuthProvider>
            <CookieConsentProvider>
              {children}
              <CookieConsentBanner />
            </CookieConsentProvider>
          </AuthProvider>
        </EditionProvider>
      </body>
    </html>
  );
}
