import "./globals.css"
import { AppShell } from "@/components/layout/app-shell"
import { AppSettingsProvider } from "@/components/providers/app-settings-provider"
import { AuthProvider } from "@/components/providers/auth-provider"
import { ToastProvider } from "@/components/ui/toast"

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning className="dark font-sans">
      <body className="min-h-screen bg-background text-foreground antialiased">
        <AppSettingsProvider>
          <ToastProvider>
            <AuthProvider>
              <AppShell>{children}</AppShell>
            </AuthProvider>
          </ToastProvider>
        </AppSettingsProvider>
      </body>
    </html>
  )
}
