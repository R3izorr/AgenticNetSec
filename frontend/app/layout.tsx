import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AgenticNetSec Console",
  description: "Network forensic dashboard shell for AgenticNetSec",
};

const navItems = ["Overview", "Findings", "Timeline", "Playbooks"];

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} min-h-screen antialiased`}
      >
        <div className="relative min-h-screen overflow-x-hidden bg-[radial-gradient(circle_at_top_right,var(--color-ink-soft),transparent_48%),linear-gradient(155deg,var(--color-bg),var(--color-bg-alt))] text-[var(--color-text)]">
          <header className="border-b border-[var(--color-border)]/70 backdrop-blur">
            <div className="mx-auto flex w-full max-w-6xl items-center justify-between px-6 py-5">
              <div>
                <p className="font-mono text-xs uppercase tracking-[0.28em] text-[var(--color-accent)]">
                  AgenticNetSec
                </p>
                <h1 className="mt-2 text-xl font-semibold">Forensic Operations Console</h1>
              </div>
              <nav className="hidden gap-2 md:flex" aria-label="Primary navigation">
                {navItems.map((item) => (
                  <button
                    key={item}
                    type="button"
                    className="rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm text-[var(--color-text-muted)] transition hover:text-[var(--color-text)]"
                  >
                    {item}
                  </button>
                ))}
              </nav>
            </div>
          </header>
          <main className="mx-auto w-full max-w-6xl px-6 py-8">{children}</main>
        </div>
      </body>
    </html>
  );
}
