import type { Metadata, Viewport } from "next";
import { Providers } from "@/components/providers";
import "@/globals.css";

export const metadata: Metadata = {
  title: "access-hub",
  description: "One identity for every workspace.",
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#093F3F",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-dvh font-sans antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
