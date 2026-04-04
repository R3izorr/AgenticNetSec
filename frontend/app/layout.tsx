import "./globals.css"
import { Geist } from "next/font/google"
import { AppShell } from "@/components/layout/app-shell"
import { AppSettingsProvider } from "@/components/providers/app-settings-provider"
import { ToastProvider } from "@/components/ui/toast"
import { cn } from "@/lib/utils"

const geist = Geist({ subsets: ["latin"], variable: "--font-sans" })

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning className={cn("dark font-sans", geist.variable)}>
      <body className="min-h-screen bg-background text-foreground antialiased">
        <AppSettingsProvider>
          <ToastProvider>
            <AppShell>{children}</AppShell>
          </ToastProvider>
        </AppSettingsProvider>
      </body>
    </html>
  )
}
