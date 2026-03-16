"use client"

import Link from "next/link"
import { useMemo } from "react"
import { useParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { ProgressBar } from "@/components/common/progress-bar"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { useJobStatus } from "@/hooks/use-job-status"
import { formatDateTime, formatPercent } from "@/lib/format"

const pipelinePhases = [
  { id: "queued", label: "Queued", threshold: 0.0 },
  { id: "ingest", label: "Ingest", threshold: 0.2 },
  { id: "parse", label: "Parse", threshold: 0.35 },
  { id: "analysis", label: "Detect/Analyze", threshold: 0.55 },
  { id: "reason", label: "Reason", threshold: 0.75 },
  { id: "report", label: "Report", threshold: 0.9 },
  { id: "completed", label: "Completed", threshold: 1.0 },
]

export default function AnalysisJobPage() {
  const params = useParams<{ jobId: string }>()
  const jobId = decodeURIComponent(params.jobId)
  const { job, loading, error, refresh, isPolling, lastUpdatedAt } = useJobStatus(jobId)

  const phaseStates = useMemo(() => {
    return pipelinePhases.map((phase) => {
      if (job?.status.toLowerCase() === "failed") {
        return {
          ...phase,
          state: phase.id === "completed" ? "pending" : "failed",
        }
      }

      const progress = job?.progress ?? 0
      if (progress >= phase.threshold) {
        return { ...phase, state: "done" }
      }
      return { ...phase, state: "pending" }
    })
  }, [job?.progress, job?.status])

  if (loading && !job) {
    return <LoadingState title="Loading job status" description={`Job: ${jobId}`} />
  }

  if (!job && error) {
    return <ErrorState title="Unable to load job" description={error} onRetry={refresh} />
  }

  if (!job) {
    return <EmptyState title="Job not found" description="No status data returned." />
  }

  return (
    <div className="space-y-6">
      <SectionCard
        title="Analysis Job"
        subtitle="Track asynchronous execution and open generated artifacts."
        actions={
          <Button size="sm" variant="outline" onClick={() => void refresh()}>
            Refresh
          </Button>
        }
      >
        <KeyValueGrid
          items={[
            { label: "Job ID", value: <code className="text-xs">{job.analysisJobId}</code> },
            { label: "Status", value: <StatusBadge value={job.status} /> },
            { label: "Current Phase", value: job.currentPhase },
            { label: "Progress", value: formatPercent(job.progress) },
            { label: "Guardrail State", value: <StatusBadge value={job.guardrailState} /> },
            {
              label: "Last Updated",
              value: lastUpdatedAt ? formatDateTime(lastUpdatedAt) : "Not yet",
            },
          ]}
        />

        <div className="mt-4 space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Pipeline Progress</span>
            <span>{formatPercent(job.progress)}</span>
          </div>
          <ProgressBar value={job.progress} />
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Button asChild size="sm">
            <Link href={`/analysis/${job.analysisJobId}/report`}>Open Report</Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link href={`/analysis/${job.analysisJobId}/raw`}>Open Raw Artifacts</Link>
          </Button>
          <span className="text-xs text-muted-foreground">
            Polling: {isPolling ? "active (3s)" : "stopped"}
          </span>
        </div>

        {job.error ? (
          <p className="mt-4 rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm text-red-200">
            {job.error}
          </p>
        ) : null}

        {error && job ? (
          <p className="mt-4 rounded-md border border-yellow-500/30 bg-yellow-500/5 px-3 py-2 text-sm text-yellow-200">
            {error}
          </p>
        ) : null}
      </SectionCard>

      <SectionCard title="Progress Timeline" subtitle="Conceptual forensic pipeline stages.">
        <ol className="space-y-2">
          {phaseStates.map((phase) => {
            const className =
              phase.state === "done"
                ? "border-green-500/30 bg-green-500/10 text-green-200"
                : phase.state === "failed"
                  ? "border-red-500/30 bg-red-500/10 text-red-200"
                  : "border-border bg-background/40 text-muted-foreground"
            return (
              <li key={phase.id} className={`rounded-md border px-3 py-2 text-sm ${className}`}>
                {phase.label}
              </li>
            )
          })}
        </ol>
      </SectionCard>
    </div>
  )
}
