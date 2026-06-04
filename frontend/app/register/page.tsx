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

function RegisterForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { authenticated, loading, register } = useAuth()
  const [displayName, setDisplayName] = useState("")
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
    if (password.length < 8) {
      setFormError("Password must be at least 8 characters.")
      return
    }

    setSubmitting(true)
    try {
      await register({
        email,
        password,
        displayName: displayName.trim() || undefined,
      })
      router.replace(nextPath)
    } catch (error) {
      const message = isApiError(error)
        ? error.detail || error.message
        : error instanceof Error
          ? error.message
          : "Registration failed."
      setFormError(message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10">
      <div className="mb-6">
        <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec</p>
        <h1 className="mt-2 text-2xl font-semibold">Create account</h1>
      </div>
      <SectionCard title="Register" subtitle="Registration creates your default organization and owner membership.">
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <div className="flex flex-col gap-2">
            <Label htmlFor="display-name">Display name</Label>
            <Input
              id="display-name"
              autoComplete="name"
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </div>
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
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              minLength={8}
              required
            />
          </div>
          {formError ? <InlineNotice variant="error">{formError}</InlineNotice> : null}
          <div className="flex items-center justify-between gap-3">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Creating..." : "Create account"}
            </Button>
            <Button asChild variant="ghost">
              <Link href="/login">Sign in</Link>
            </Button>
          </div>
        </form>
      </SectionCard>
    </main>
  )
}

export default function RegisterPage() {
  return (
    <Suspense
      fallback={
        <main className="mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-4 py-10 text-sm text-muted-foreground">
          Loading...
        </main>
      }
    >
      <RegisterForm />
    </Suspense>
  )
}
