"use client"

import Link from "next/link"
import { useMemo } from "react"
import { useParams } from "next/navigation"

import { InlineNotice } from "@/components/common/inline-notice"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { ProgressBar } from "@/components/common/progress-bar"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { useJobStatus } from "@/hooks/use-job-status"
import {
  formatBytes,
  formatDateTime,
  formatNumber,
  formatPercent,
  formatPhaseLabel,
} from "@/lib/format"
import { cn } from "@/lib/utils"

const phaseOrder = ["queued", "ingest", "parse", "analysis", "reason", "report", "completed"] as const

const phaseStyles = {
  done: "border-green-500/30 bg-green-500/10 text-green-200",
  active: "border-blue-500/30 bg-blue-500/10 text-blue-100",
  failed: "border-red-500/30 bg-red-500/10 text-red-200",
  pending: "border-border/70 bg-background/40 text-muted-foreground",
} as const

type PhaseState = keyof typeof phaseStyles

type TimelinePhase = {
  id: (typeof phaseOrder)[number]
  label: string
  state: PhaseState
}

function ArtifactBadge({ label, ready }: { label: string; ready: boolean }) {
  return (
    <Badge variant="secondary" className="rounded-full px-2.5 py-0.5">
      {label}: {ready ? "ready" : "pending"}
    </Badge>
  )
}

export default function AnalysisJobPage() {
  const params = useParams<{ jobId: string }>()
  const jobId = decodeURIComponent(params.jobId)
  const { job, loading, error, refresh, isPolling, lastUpdatedAt } = useJobStatus(jobId)

  const phaseStates = useMemo<TimelinePhase[]>(() => {
    const currentIndex = phaseOrder.indexOf((job?.currentPhase ?? "queued") as (typeof phaseOrder)[number])

    return phaseOrder.map((phase, index) => {
      let state: PhaseState = "pending"
      if (job?.status.toLowerCase() === "failed") {
        state = index < currentIndex ? "done" : index === currentIndex ? "failed" : "pending"
      } else if (job?.status.toLowerCase() === "completed") {
        state = "done"
      } else if (currentIndex === -1) {
        state = phase === "queued" ? "active" : "pending"
      } else if (index < currentIndex) {
        state = "done"
      } else if (index === currentIndex) {
        state = "active"
      }

      return {
        id: phase,
        label: formatPhaseLabel(phase),
        state,
      }
    })
  }, [job?.currentPhase, job?.status])

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
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Analysis Job"
        subtitle="Track asynchronous execution, metadata, and generated artifacts."
        actions={
          <Button size="sm" variant="outline" onClick={() => void refresh()}>
            Refresh
          </Button>
        }
      >
        <div className="flex flex-col gap-4">
          <KeyValueGrid
            items={[
              { label: "Job ID", value: <code className="text-xs">{job.analysisJobId}</code> },
              { label: "Status", value: <StatusBadge value={job.status} /> },
              { label: "Current Phase", value: formatPhaseLabel(job.currentPhase) },
              { label: "Progress", value: formatPercent(job.progress) },
              { label: "Guardrail State", value: <StatusBadge value={job.guardrailState} /> },
              { label: "Input Source", value: job.sourceType ?? "N/A" },
              { label: "Source Name", value: job.sourceName ?? "N/A" },
              {
                label: "Submitted At",
                value: job.createdAt ? formatDateTime(job.createdAt) : "N/A",
              },
              {
                label: "Last Updated",
                value: job.updatedAt ? formatDateTime(job.updatedAt) : lastUpdatedAt ? formatDateTime(lastUpdatedAt) : "N/A",
              },
              {
                label: "Capture Window",
                value:
                  job.metadata.captureStart && job.metadata.captureEnd
                    ? `${formatDateTime(job.metadata.captureStart)} -> ${formatDateTime(job.metadata.captureEnd)}`
                    : "N/A",
              },
              {
                label: "File Size",
                value: formatBytes(job.metadata.sizeBytes),
              },
              {
                label: "Packets / Flows",
                value:
                  job.metadata.packetCount === null && job.metadata.flowCount === null
                    ? "N/A"
                    : `${job.metadata.packetCount ?? "?"} / ${job.metadata.flowCount ?? "?"}`,
              },
              {
                label: "Runtime",
                value:
                  job.runtimeSecondsTotal === null
                    ? "N/A"
                    : `${formatNumber(job.runtimeSecondsTotal, 3)} s`,
              },
              {
                label: "Risk Level",
                value: job.riskLevel ? <StatusBadge value={job.riskLevel} /> : "N/A",
              },
              {
                label: "Confidence",
                value:
                  job.confidenceScore === null
                    ? "N/A"
                    : `${formatNumber(job.confidenceScore, 3)} / 1.000`,
              },
            ]}
          />

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Pipeline Progress</span>
              <span>{formatPercent(job.progress)}</span>
            </div>
            <ProgressBar value={job.progress} />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button asChild size="sm">
              <Link href={`/analysis/${job.analysisJobId}/report`}>Open Report</Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link href={`/analysis/${job.analysisJobId}/raw`}>Open Raw Artifacts</Link>
            </Button>
            <Badge variant="secondary" className="rounded-full px-2.5 py-0.5">
              Polling: {isPolling ? "active (3s)" : "stopped"}
            </Badge>
          </div>

          <div className="flex flex-wrap gap-2">
            <ArtifactBadge label="Report JSON" ready={job.artifactReady.reportJson} />
            <ArtifactBadge label="Report MD" ready={job.artifactReady.reportMarkdown} />
            <ArtifactBadge label="Metrics" ready={job.artifactReady.metrics} />
            <ArtifactBadge label="Guardrails" ready={job.artifactReady.guardrailAudit} />
          </div>

          {job.sourcePath ? (
            <InlineNotice variant="info" title="Backend Path">
              <code className="text-xs">{job.sourcePath}</code>
            </InlineNotice>
          ) : null}
          {job.error ? <InlineNotice variant="error">{job.error}</InlineNotice> : null}
          {error && job ? <InlineNotice variant="warning">{error}</InlineNotice> : null}
        </div>
      </SectionCard>

      <SectionCard title="Execution Timeline" subtitle="Backend-driven forensic pipeline stages.">
        <ol className="flex flex-col gap-2">
          {phaseStates.map((phase) => (
            <li
              key={phase.id}
              className={cn("rounded-md border px-3 py-2 text-sm", phaseStyles[phase.state])}
            >
              <div className="flex items-center justify-between gap-3">
                <span>{phase.label}</span>
                {phase.id === job.currentPhase || (phase.id === "completed" && job.status === "completed") ? (
                  <StatusBadge value={job.status === "failed" && phase.id === job.currentPhase ? "failed" : phase.state === "done" ? "completed" : "running"} />
                ) : null}
              </div>
            </li>
          ))}
        </ol>
      </SectionCard>
    </div>
  )
}

