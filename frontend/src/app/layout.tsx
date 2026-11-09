import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cerebro | Cybersecurity Intelligence",
  description: "AI-Powered Cybersecurity Intelligence Assistant. Think smarter. Investigate deeper.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
