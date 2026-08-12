import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "localhost";
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (host.startsWith("localhost") ? "http" : "https");
  const origin = `${protocol}://${host}`;

  return {
    metadataBase: new URL(origin),
    title: "Mathews System Field Guide",
    description: "The complete interactive field guide for Mathews architecture, workflow, authority, evidence, recovery, operations, and acceptance.",
    icons: {
      icon: "/favicon.svg",
      shortcut: "/favicon.svg",
    },
    openGraph: {
      title: "Mathews System Field Guide",
      description: "The complete field guide for evidence-first iOS engineering and human-controlled delivery.",
      images: [{ url: `${origin}/og-complete-guide.png`, width: 1728, height: 910, alt: "Complete Mathews System Field Guide" }],
    },
    twitter: {
      card: "summary_large_image",
      title: "Mathews System Field Guide",
      description: "The complete field guide for evidence-first iOS engineering and human-controlled delivery.",
      images: [`${origin}/og-complete-guide.png`],
    },
  };
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
