import Link from "next/link"

import { SectionCard } from "@/components/common/section-card"
import { Button } from "@/components/ui/button"

const highlights = [
  {
    title: "PCAP Ingestion",
    description: "Submit one PCAP file or one pcap_path and trigger autonomous execution.",
  },
  {
    title: "Async Job Tracking",
    description: "Observe queued/running/completed/failed lifecycle with 3-second polling.",
  },
  {
    title: "Structured Forensic Report",
    description: "Review evidence, timeline, findings, impact, recommendations, and guardrail checks.",
  },
  {
    title: "Raw Artifacts & Metrics",
    description: "Inspect report.json, markdown output, and runtime/cost metrics for demo credibility.",
  },
  {
    title: "Ingestion History",
    description: "View all submitted PCAP analyses with status, timestamps, and quick access to details.",
  },
]

export default function HomePage() {
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
            Built for submission demos: submit PCAPs, monitor asynchronous analysis, and present
            analyst-ready findings with guardrails and runtime/cost visibility.
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <Button asChild>
              <Link href="/analysis/new">Start Analysis</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link href="/analysis/history">View History</Link>
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
