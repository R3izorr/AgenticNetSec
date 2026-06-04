"use client"

import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { Suspense, useEffect, useState } from "react"

import { InlineNotice } from "@/components/common/inline-notice"
import { SectionCard } from "@/components/common/section-card"
import { useAuth } from "@/components/providers/auth-provider"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { isApiError } from "@/lib/api/client"

function LoginForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { authenticated, loading, login } = useAuth()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const nextPath = searchParams.get("next") || "/dashboard"

  useEffect(() => {
    if (!loading && authenticated) {
      router.replace(nextPath)
    }
  }, [authenticated, loading, nextPath, router])

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setFormError(null)
    setSubmitting(true)
    try {
      await login({ email, password })
      router.replace(nextPath)
    } catch (error) {
      const message = isApiError(error)
        ? error.detail || error.message
        : error instanceof Error
          ? error.message
          : "Login failed."
      setFormError(message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10">
      <div className="mb-6">
        <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec</p>
        <h1 className="mt-2 text-2xl font-semibold">Sign in</h1>
      </div>
      <SectionCard title="Login" subtitle="Use your MVP account to access analyses and reports.">
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <div className="flex flex-col gap-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          {formError ? <InlineNotice variant="error">{formError}</InlineNotice> : null}
          <div className="flex items-center justify-between gap-3">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Signing in..." : "Sign in"}
            </Button>
            <Button asChild variant="ghost">
              <Link href="/register">Create account</Link>
            </Button>
          </div>
        </form>
      </SectionCard>
    </main>
  )
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10 text-sm text-muted-foreground">
          Loading...
        </main>
      }
    >
      <LoginForm />
    </Suspense>
  )
}
