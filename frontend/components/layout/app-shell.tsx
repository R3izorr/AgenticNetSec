"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { LogOutIcon } from "lucide-react"
import { useEffect, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuth } from "@/components/providers/auth-provider"
import { canCreateAnalysis } from "@/lib/permissions"
import { cn } from "@/lib/utils"

const navLinks = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/analysis/new", label: "New Analysis" },
  { href: "/total-jobs", label: "Total Jobs" },
  { href: "/analysis/history", label: "History" },
  { href: "/settings", label: "Settings" },
]
const publicRoutes = new Set(["/login", "/register"])

function isActiveRoute(pathname: string, href: string) {
  if (href === "/dashboard") {
    return pathname === "/" || pathname === "/dashboard"
  }
  if (href === "/analysis/history") {
    return pathname === href
  }
  return pathname === href || pathname.startsWith(`${href}/`)
}

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

  const role = session?.organization.role ?? "viewer"
  const roleLabel = role.charAt(0).toUpperCase() + role.slice(1)

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/90 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-3 px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec</p>
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <h1 className="text-base font-semibold">Forensic Workspace</h1>
              <Badge variant="secondary" className="rounded-full px-2.5 py-0.5">
                {roleLabel}
              </Badge>
            </div>
            <p className="mt-1 truncate text-xs text-muted-foreground">
              {session?.user.email} / {session?.organization.name}
            </p>
          </div>

          <nav className="flex flex-wrap items-center gap-2">
            {navLinks
              .filter((link) => link.href !== "/analysis/new" || canCreateAnalysis(session?.organization.role))
              .map((link) => {
                const active = isActiveRoute(pathname, link.href)
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

          <form className="flex w-full flex-wrap items-center gap-2 lg:w-auto" onSubmit={onJumpSubmit}>
            <label htmlFor="jump-job-id" className="sr-only">
              Jump to Job ID
            </label>
            <Input
              id="jump-job-id"
              value={jobId}
              onChange={(event) => setJobId(event.target.value)}
              placeholder="Jump to Job ID"
              className="h-8 min-w-0 flex-1 bg-card sm:w-52 sm:flex-none"
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
