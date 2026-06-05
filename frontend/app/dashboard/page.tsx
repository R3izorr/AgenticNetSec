"use client"

import Link from "next/link"
import type { ReactNode } from "react"

import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { useAuth } from "@/components/providers/auth-provider"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useJobHistory } from "@/hooks/use-job-history"
import { formatDateTime, formatNumber, formatPhaseLabel } from "@/lib/format"
import { canCreateAnalysis } from "@/lib/permissions"

function SummaryCard({
  title,
  value,
  hint,
}: {
  title: string
  value: ReactNode
  hint: string
}) {
  return (
    <Card className="border border-border/70 bg-card/95 shadow-sm">
      <CardHeader className="gap-1 pb-3">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">{title}</p>
        <CardTitle className="text-2xl">{value}</CardTitle>
      </CardHeader>
      <CardContent className="pt-0 text-sm text-muted-foreground">{hint}</CardContent>
    </Card>
  )
}

export default function DashboardPage() {
  const { session } = useAuth()
  const mayCreateAnalysis = canCreateAnalysis(session?.organization.role)
  const { jobs, loading, error, refresh, summary } = useJobHistory()
  const latestCompletedJob = summary.recentJobs.find((job) => job.status === "completed")

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <LoadingState
          title="Loading dashboard"
          description="Fetching recent analyses, guardrail outcomes, and runtime summaries."
        />
      </div>
    )
  }

  if (error && !jobs.length) {
    return (
      <div className="flex flex-col gap-6">
        <ErrorState title="Unable to load dashboard" description={error} onRetry={() => void refresh()} />
      </div>
    )
  }

  if (!jobs.length) {
    return (
      <div className="flex flex-col gap-6">
        <EmptyState
          title="No analyses yet"
          description="Start with a PCAP submission to populate the dashboard with status, risk, and runtime data."
          action={
            <div className="flex items-center gap-2">
              {mayCreateAnalysis ? (
                <Button asChild>
                  <Link href="/analysis/new">Start Analysis</Link>
                </Button>
              ) : null}
              <Button variant="outline" asChild>
                <Link href="/analysis/history">Open History</Link>
              </Button>
            </div>
          }
        />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="relative overflow-hidden rounded-2xl border border-border bg-card p-8">
        <div className="relative z-10 flex max-w-4xl flex-col gap-4">
          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">AgenticNetSec Dashboard</p>
          <h1 className="text-3xl font-semibold leading-tight sm:text-4xl">
            Recent network forensic analysis
          </h1>
          <p className="text-sm text-muted-foreground sm:text-base">
            Track persisted jobs, failures, risk ranking, runtime, and report readiness across this organization.
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-2">
            {mayCreateAnalysis ? (
              <Button asChild>
                <Link href="/analysis/new">Start Analysis</Link>
              </Button>
            ) : null}
            <Button variant="outline" asChild>
              <Link href="/analysis/history">Open History</Link>
            </Button>
            {latestCompletedJob ? (
              <Button variant="outline" asChild>
                <Link href={`/analysis/${latestCompletedJob.analysisJobId}/report`}>Latest Report</Link>
              </Button>
            ) : null}
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <SummaryCard title="Total Jobs" value={summary.totalJobs} hint="All persisted analyses visible to the API." />
        <SummaryCard title="Running Jobs" value={summary.runningJobs} hint="Queued jobs are tracked separately in history." />
        <SummaryCard title="Completed Jobs" value={summary.completedJobs} hint="Ready for report/raw artifact walkthroughs." />
        <SummaryCard title="Failed Jobs" value={summary.failedJobs} hint="Useful for demonstrating edge-case handling." />
      </section>

      <section className="grid gap-4 xl:grid-cols-[2fr_1fr]">
        <SectionCard
          title="Recent Analyses"
          subtitle="Newest runs with status, phase, and quick report access."
          actions={
            <Button variant="outline" size="sm" onClick={() => void refresh()}>
              Refresh
            </Button>
          }
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Job</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Phase</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead>Runtime</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {summary.recentJobs.map((job) => (
                <TableRow key={job.analysisJobId}>
                  <TableCell>
                    <div className="flex flex-col gap-1">
                      <span className="font-mono text-xs text-foreground/80">{job.analysisJobId}</span>
                      <span className="text-xs text-muted-foreground">{job.sourceName ?? "N/A"}</span>
                    </div>
                  </TableCell>
                  <TableCell><StatusBadge value={job.status} /></TableCell>
                  <TableCell className="text-sm text-foreground/70">{formatPhaseLabel(job.currentPhase)}</TableCell>
                  <TableCell>
                    {job.riskLevel ? <StatusBadge value={job.riskLevel} /> : <span className="text-sm text-muted-foreground">-</span>}
                  </TableCell>
                  <TableCell className="text-sm text-foreground/70">
                    {job.runtimeSecondsTotal === null ? "-" : `${formatNumber(job.runtimeSecondsTotal, 3)} s`}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDateTime(job.updatedAt ?? job.createdAt ?? "N/A")}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button asChild size="sm" variant="ghost">
                      <Link
                        href={
                          job.status === "completed"
                            ? `/analysis/${job.analysisJobId}/report`
                            : `/analysis/${job.analysisJobId}`
                        }
                      >
                        {job.status === "completed" ? "Report" : "Open"}
                      </Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </SectionCard>

        <div className="flex flex-col gap-4">
          <SectionCard title="Guardrail Snapshot" subtitle="Quick counts for demo narration.">
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between rounded-md border border-border/70 bg-background/40 px-3 py-2 text-sm">
                <span>Human Review Required</span>
                <span>{summary.humanReviewRequiredJobs}</span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-border/70 bg-background/40 px-3 py-2 text-sm">
                <span>Guardrail Clear</span>
                <span>{summary.guardrailClearJobs}</span>
              </div>
              <div className="flex items-center justify-between rounded-md border border-border/70 bg-background/40 px-3 py-2 text-sm">
                <span>Average Runtime</span>
                <span>
                  {summary.averageRuntimeSeconds === null
                    ? "N/A"
                    : `${formatNumber(summary.averageRuntimeSeconds, 3)} s`}
                </span>
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Top Risk / Confidence" subtitle="Best candidates for a report walkthrough.">
            <div className="flex flex-col gap-3">
              {summary.riskyJobs.length ? summary.riskyJobs.map((job) => (
                <div key={job.analysisJobId} className="rounded-md border border-border/70 bg-background/40 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <code className="text-xs">{job.analysisJobId}</code>
                    {job.riskLevel ? <StatusBadge value={job.riskLevel} /> : null}
                  </div>
                  <p className="mt-2 text-sm text-foreground/80">{job.sourceName ?? "Unknown source"}</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Confidence: {job.confidenceScore === null ? "N/A" : formatNumber(job.confidenceScore, 3)}
                  </p>
                  <div className="mt-3 flex items-center gap-2">
                    <Button asChild size="sm" variant="outline">
                      <Link href={`/analysis/${job.analysisJobId}/report`}>Report</Link>
                    </Button>
                    <Button asChild size="sm" variant="ghost">
                      <Link href={`/analysis/${job.analysisJobId}/raw`}>Raw</Link>
                    </Button>
                  </div>
                </div>
              )) : (
                <p className="text-sm text-muted-foreground">No completed jobs with risk/confidence data yet.</p>
              )}
            </div>
          </SectionCard>
        </div>
      </section>
    </div>
  )
}
