import type { Metadata, Viewport } from 'next';
import './globals.css';
export const metadata: Metadata = {
  title: 'Local Sandbox · Agent control room',
  description: 'Guide your iOS agents, build bounded Shortcuts workflows, and inspect every result.',
  manifest: '/manifest.webmanifest',
  appleWebApp: { capable: true, title: 'Local Sandbox', statusBarStyle: 'black-translucent' },
  icons: { icon: '/favicon.svg', shortcut: '/favicon.svg' },
};
export const viewport: Viewport = { width: 'device-width', initialScale: 1, themeColor: '#0b0d0d' };
export default function RootLayout({children}: Readonly<{children: React.ReactNode}>) {
  return <html lang="en" className="dark"><body>{children}</body></html>;
}
