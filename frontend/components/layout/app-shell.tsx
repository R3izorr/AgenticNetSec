"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { LogOutIcon } from "lucide-react"
import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuth } from "@/components/providers/auth-provider"
import { canCreateAnalysis } from "@/lib/permissions"
import { cn } from "@/lib/utils"

const navLinks = [
  { href: "/", label: "Overview" },
  { href: "/dashboard", label: "Dashboard" },
  { href: "/analysis/new", label: "New Analysis" },
  { href: "/total-jobs", label: "Total Jobs" },
  { href: "/analysis/history", label: "History" },
  { href: "/settings", label: "Settings" },
]
const publicRoutes = new Set(["/login", "/register"])

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const { authenticated, loading, logout, session } = useAuth()
  const [jobId, setJobId] = useState("")
  const [loggingOut, setLoggingOut] = useState(false)
  const isPublicRoute = publicRoutes.has(pathname)

  useEffect(() => {
    if (!loading && !authenticated && !isPublicRoute) {
      const next = encodeURIComponent(pathname || "/dashboard")
      router.replace(`/login?next=${next}`)
    }
  }, [authenticated, isPublicRoute, loading, pathname, router])

  function onJumpSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalized = jobId.trim()
    if (!normalized) {
      return
    }
    router.push(`/analysis/${encodeURIComponent(normalized)}`)
  }

  async function onLogout() {
    setLoggingOut(true)
    try {
      await logout()
      router.replace("/login")
    } finally {
      setLoggingOut(false)
    }
  }

  if (isPublicRoute) {
    return <div className="min-h-screen bg-background text-foreground">{children}</div>
  }

  if (loading || !authenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        Loading session...
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/90 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec</p>
            <h1 className="text-base font-semibold">Network Forensic Frontend v1</h1>
            <p className="mt-1 text-xs text-muted-foreground">
              {session?.user.email} - {session?.organization.name}
            </p>
          </div>

          <nav className="flex items-center gap-2">
            {navLinks
              .filter((link) => link.href !== "/analysis/new" || canCreateAnalysis(session?.organization.role))
              .map((link) => {
                const active = pathname === link.href
                return (
                <Button
                  key={link.href}
                  asChild
                  size="sm"
                  variant={active ? "secondary" : "ghost"}
                  className={cn(active && "shadow-sm")}
                >
                    <Link href={link.href}>{link.label}</Link>
                  </Button>
                )
              })}
          </nav>

          <form className="flex items-center gap-2" onSubmit={onJumpSubmit}>
            <label htmlFor="jump-job-id" className="sr-only">
              Jump to Job ID
            </label>
            <Input
              id="jump-job-id"
              value={jobId}
              onChange={(event) => setJobId(event.target.value)}
              placeholder="Jump to Job ID"
              className="h-8 w-44 bg-card"
            />
            <Button type="submit" size="sm">
              Open
            </Button>
            <Button
              type="button"
              size="icon"
              variant="ghost"
              onClick={() => void onLogout()}
              disabled={loggingOut}
              title="Log out"
              aria-label="Log out"
            >
              <LogOutIcon className="size-4" />
            </Button>
          </form>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl px-4 py-6">{children}</main>
    </div>
  )
}
