"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const navLinks = [
  { href: "/", label: "Overview" },
  { href: "/analysis/new", label: "New Analysis" },
]

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()
  const [jobId, setJobId] = useState("")

  function onJumpSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const normalized = jobId.trim()
    if (!normalized) {
      return
    }
    router.push(`/analysis/${encodeURIComponent(normalized)}`)
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/90 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec</p>
            <h1 className="text-base font-semibold">Network Forensic Frontend v1</h1>
          </div>

          <nav className="flex items-center gap-2">
            {navLinks.map((link) => {
              const active = pathname === link.href
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={cn(
                    "rounded-md px-3 py-1.5 text-sm transition-colors",
                    active
                      ? "bg-primary/20 text-foreground"
                      : "text-muted-foreground hover:bg-muted"
                  )}
                >
                  {link.label}
                </Link>
              )
            })}
          </nav>

          <form className="flex items-center gap-2" onSubmit={onJumpSubmit}>
            <label htmlFor="jump-job-id" className="sr-only">
              Jump to Job ID
            </label>
            <input
              id="jump-job-id"
              value={jobId}
              onChange={(event) => setJobId(event.target.value)}
              placeholder="Jump to Job ID"
              className="h-8 w-44 rounded-md border border-input bg-card px-2 text-sm outline-none focus:border-ring"
            />
            <Button type="submit" size="sm">
              Open
            </Button>
          </form>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl px-4 py-6">{children}</main>
    </div>
  )
}
