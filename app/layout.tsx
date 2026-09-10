import type { Metadata, Viewport } from 'next';
import './globals.css';
export const metadata: Metadata = {
  title: 'Local Sandbox · Agent control room',
  description: 'Guide your iOS agents, build bounded Shortcuts workflows, and inspect every result.',
  manifest: '/manifest.webmanifest',
  appleWebApp: { capable: true, title: 'Local Sandbox', statusBarStyle: 'black-translucent' },
  icons: { icon: '/app-icon.png', shortcut: '/app-icon.png', apple: '/app-icon.png' },
};
export const viewport: Viewport = { width: 'device-width', initialScale: 1, themeColor: [{media:'(prefers-color-scheme: light)',color:'#f5f5f7'},{media:'(prefers-color-scheme: dark)',color:'#111112'}] };
export default function RootLayout({children}: Readonly<{children: React.ReactNode}>) {
  return <html lang="en" ><body>{children}</body></html>;
}
