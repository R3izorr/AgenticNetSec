"use client"

import Link from "next/link"

import { SectionCard } from "@/components/common/section-card"
import { useAuth } from "@/components/providers/auth-provider"
import { Button } from "@/components/ui/button"
import { canCreateAnalysis } from "@/lib/permissions"

const highlights = [
  {
    title: "Command Dashboard",
    description: "Open a demo-ready command view with recent jobs, risk ranking, runtime summaries, and guardrail outcomes.",
  },
  {
    title: "Batch Ingestion",
    description: "Submit one or many PCAP files in a single batch and track them under one total job.",
  },
  {
    title: "Deterministic First Pass",
    description: "Run code-only analysis first, then trigger AI summary and sandbox later when the batch is ready.",
  },
  {
    title: "Structured Forensic Report",
    description: "Review evidence, timeline, findings, impact, recommendations, and guardrail checks.",
  },
  {
    title: "Raw Artifacts & Metrics",
    description: "Inspect report.json, markdown output, and runtime or cost metrics for demo credibility.",
  },
  {
    title: "Ingestion History",
    description: "View all submitted PCAP analyses with source, timestamps, risk, and quick access to details.",
  },
]

export default function HomePage() {
  const { session } = useAuth()
  const mayCreateAnalysis = canCreateAnalysis(session?.organization.role)

  return (
    <div className="flex flex-col gap-6">
      <section className="relative overflow-hidden rounded-2xl border border-border bg-card p-8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(59,130,246,0.14),transparent_35%)]" />
        <div className="relative z-10 flex max-w-3xl flex-col gap-4">
          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec v1</p>
          <h1 className="text-3xl font-semibold leading-tight sm:text-4xl">
            Autonomous Network Forensic Analysis Frontend
          </h1>
          <p className="text-sm text-muted-foreground sm:text-base">
            Built for submission demos: start on the dashboard, jump into recent analyses, and present analyst-ready findings with guardrails plus runtime visibility.
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <Button asChild>
              <Link href="/dashboard">Open Dashboard</Link>
            </Button>
            {mayCreateAnalysis ? (
              <Button variant="outline" asChild>
                <Link href="/analysis/new">Start Batch</Link>
              </Button>
            ) : null}
            <Button variant="ghost" asChild>
              <Link href="/total-jobs">View Total Jobs</Link>
            </Button>
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2">
        {highlights.map((item) => (
          <SectionCard key={item.title} title={item.title}>
            <p className="text-sm text-muted-foreground">{item.description}</p>
          </SectionCard>
        ))}
      </section>
    </div>
  )
}
