"use client"

import Link from "next/link"
import { useCallback, useEffect, useMemo, useState } from "react"
import { useParams } from "next/navigation"

import { ArtifactPanel } from "@/components/common/artifact-panel"
import { InlineNotice } from "@/components/common/inline-notice"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { ProgressBar } from "@/components/common/progress-bar"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  getTotalJobSandbox,
  getTotalJobSummaryJson,
  getTotalJobSummaryMarkdown,
  triggerTotalJobEnrichment,
} from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { useTotalJobStatus } from "@/hooks/use-total-job-status"
import { formatDateTime, formatNumber, formatPercent, formatPhaseLabel } from "@/lib/format"

type EnrichmentArtifacts = {
  summaryJson: unknown | null
  summaryMarkdown: string | null
  sandbox: unknown | null
}

const EMPTY_ARTIFACTS: EnrichmentArtifacts = {
  summaryJson: null,
  summaryMarkdown: null,
  sandbox: null,
}

type DedupeInfo = {
  strategy: string | null
  inputRecordCount: number
  uniqueRecordCount: number
  duplicateRecordCount: number
  duplicatesRemoved: Array<{
    file: string | null
    path: string | null
    dedupeKey: string | null
  }>
}

function parseDedupeInfo(value: unknown): DedupeInfo | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null
  }

  const source = value as Record<string, unknown>
  const dedupeRaw = source.dedupe
  if (!dedupeRaw || typeof dedupeRaw !== "object" || Array.isArray(dedupeRaw)) {
    return null
  }

  const dedupe = dedupeRaw as Record<string, unknown>
  const duplicatesRemoved = Array.isArray(dedupe.duplicates_removed)
    ? dedupe.duplicates_removed
        .filter((entry): entry is Record<string, unknown> => Boolean(entry && typeof entry === "object" && !Array.isArray(entry)))
        .map((entry) => ({
          file: typeof entry.file === "string" ? entry.file : null,
          path: typeof entry.path === "string" ? entry.path : null,
          dedupeKey: typeof entry.dedupe_key === "string" ? entry.dedupe_key : null,
        }))
    : []

  return {
    strategy: typeof dedupe.strategy === "string" ? dedupe.strategy : null,
    inputRecordCount:
      typeof dedupe.input_record_count === "number" && Number.isFinite(dedupe.input_record_count)
        ? dedupe.input_record_count
        : 0,
    uniqueRecordCount:
      typeof dedupe.unique_record_count === "number" && Number.isFinite(dedupe.unique_record_count)
        ? dedupe.unique_record_count
        : 0,
    duplicateRecordCount:
      typeof dedupe.duplicate_record_count === "number" && Number.isFinite(dedupe.duplicate_record_count)
        ? dedupe.duplicate_record_count
        : 0,
    duplicatesRemoved,
  }
}

export default function TotalJobDetailPage() {
  const params = useParams<{ totalJobId: string }>()
  const totalJobId = decodeURIComponent(params.totalJobId)
  const { job, loading, error, refresh, isPolling } = useTotalJobStatus(totalJobId)
  const [actionLoading, setActionLoading] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [artifactLoading, setArtifactLoading] = useState(false)
  const [artifactError, setArtifactError] = useState<string | null>(null)
  const [artifacts, setArtifacts] = useState<EnrichmentArtifacts>(EMPTY_ARTIFACTS)

  const loadArtifacts = useCallback(async () => {
    if (!job || job.enrichmentStatus !== "completed") {
      setArtifacts(EMPTY_ARTIFACTS)
      setArtifactError(null)
      return
    }

    setArtifactLoading(true)
    try {
      const [summaryJson, summaryMarkdown, sandbox] = await Promise.all([
        getTotalJobSummaryJson(job.totalJobId),
        getTotalJobSummaryMarkdown(job.totalJobId),
        getTotalJobSandbox(job.totalJobId),
      ])
      setArtifacts({
        summaryJson,
        summaryMarkdown: summaryMarkdown.markdown,
        sandbox,
      })
      setArtifactError(null)
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Failed to load enrichment artifacts."
      setArtifactError(message)
    } finally {
      setArtifactLoading(false)
    }
  }, [job])

  useEffect(() => {
    void loadArtifacts()
  }, [loadArtifacts])

  const handleEnrichment = async () => {
    if (!job) {
      return
    }

    setActionLoading(true)
    try {
      await triggerTotalJobEnrichment(job.totalJobId)
      setActionError(null)
      await refresh()
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Unable to trigger AI summary and sandbox."
      setActionError(message)
    } finally {
      setActionLoading(false)
    }
  }

  const childSummary = useMemo(() => {
    if (!job) {
      return {
        running: 0,
        completed: 0,
        failed: 0,
        queued: 0,
      }
    }

    return job.children.reduce(
      (acc, child) => {
        const key = child.status.toLowerCase()
        if (key === "completed") {
          acc.completed += 1
        } else if (key === "failed") {
          acc.failed += 1
        } else if (key === "running") {
          acc.running += 1
        } else {
          acc.queued += 1
        }
        return acc
      },
      { running: 0, completed: 0, failed: 0, queued: 0 }
    )
  }, [job])

  const failedChildren = useMemo(() => {
    if (!job) {
      return []
    }
    return job.children.filter((child) => child.status.toLowerCase() === "failed")
  }, [job])

  const failedChildNames = failedChildren.map((child) => child.filename)

  const dedupeInfo = useMemo(() => {
    return parseDedupeInfo(artifacts.summaryJson) ?? parseDedupeInfo(artifacts.sandbox)
  }, [artifacts.summaryJson, artifacts.sandbox])

  if (loading && !job) {
    return (
      <div className="flex flex-col gap-6">
        <LoadingState title="Loading total job" description={`Total job: ${totalJobId}`} />
      </div>
    )
  }

  if (!job && error) {
    return (
      <div className="flex flex-col gap-6">
        <ErrorState title="Unable to load total job" description={error} onRetry={() => void refresh()} />
      </div>
    )
  }

  if (!job) {
    return (
      <div className="flex flex-col gap-6">
        <EmptyState title="Total job not found" description="No batch data was returned for this identifier." />
      </div>
    )
  }

  const canRunEnrichment = job.deterministicComplete && job.enrichmentStatus !== "running"
  const summaryReady = job.enrichmentStatus === "completed"

  const enrichmentButtonLabel = actionLoading
    ? "Starting..."
    : job.enrichmentStatus === "running"
      ? "AI Summary + Sandbox Running"
      : job.enrichmentStatus === "completed"
        ? "Re-run AI Summary + Sandbox"
        : job.enrichmentStatus === "failed"
          ? "Retry AI Summary + Sandbox"
          : "Run AI Summary + Sandbox"

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Total Job"
        subtitle="Track the full batch run, child-file progress, and one parent-level summary for the whole batch."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary" className="rounded-full px-2.5 py-0.5">
              Polling: {isPolling ? "active" : "stopped"}
            </Badge>
            <Button type="button" variant="outline" onClick={() => void refresh()}>
              Refresh
            </Button>
            {summaryReady ? (
              <Button asChild type="button" variant="secondary">
                <a href="#batch-summary">Open Batch Summary</a>
              </Button>
            ) : (
              <Button type="button" variant="secondary" disabled>
                Batch Summary Pending
              </Button>
            )}
            <Button type="button" onClick={() => void handleEnrichment()} disabled={!canRunEnrichment || actionLoading}>
              {enrichmentButtonLabel}
            </Button>
          </div>
        }
      >
        <div className="flex flex-col gap-4">
          <KeyValueGrid
            items={[
              { label: "Total Job ID", value: <code className="text-xs">{job.totalJobId}</code> },
              { label: "Status", value: <StatusBadge value={job.status} /> },
              { label: "Current Stage", value: formatPhaseLabel(job.currentStage) },
              { label: "Overall Progress", value: formatPercent(job.progress) },
              { label: "Workers", value: formatNumber(job.workerCount, 0) },
              { label: "Files", value: formatNumber(job.fileCount, 0) },
              { label: "Completed Children", value: formatNumber(job.completedChildren, 0) },
              { label: "Failed Children", value: formatNumber(job.failedChildren, 0) },
              {
                label: "Deterministic Pass",
                value: job.deterministicComplete ? <StatusBadge value="completed" /> : <StatusBadge value="running" />,
              },
              { label: "Enrichment Status", value: <StatusBadge value={job.enrichmentStatus} /> },
              { label: "Created", value: job.createdAt ? formatDateTime(job.createdAt) : "N/A" },
              { label: "Updated", value: job.updatedAt ? formatDateTime(job.updatedAt) : "N/A" },
            ]}
          />

          <div className="grid gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-border/70 bg-background/40 p-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Deterministic Batch Progress</span>
                <span>{formatPercent(job.progress)}</span>
              </div>
              <div className="mt-3">
                <ProgressBar value={job.progress} />
              </div>
            </div>
            <div className="rounded-lg border border-border/70 bg-background/40 p-4">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Enrichment Progress</span>
                <span>{formatPercent(job.enrichmentProgress)}</span>
              </div>
              <div className="mt-3">
                <ProgressBar value={job.enrichmentProgress} />
              </div>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-lg border border-border/70 bg-background/40 p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Queued</p>
              <p className="mt-2 text-2xl font-semibold">{formatNumber(childSummary.queued, 0)}</p>
            </div>
            <div className="rounded-lg border border-border/70 bg-background/40 p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Running</p>
              <p className="mt-2 text-2xl font-semibold">{formatNumber(childSummary.running, 0)}</p>
            </div>
            <div className="rounded-lg border border-border/70 bg-background/40 p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Completed</p>
              <p className="mt-2 text-2xl font-semibold">{formatNumber(childSummary.completed, 0)}</p>
            </div>
            <div className="rounded-lg border border-border/70 bg-background/40 p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Failed</p>
              <p className="mt-2 text-2xl font-semibold">{formatNumber(childSummary.failed, 0)}</p>
            </div>
          </div>

          {job.error ? <InlineNotice variant="error">{job.error}</InlineNotice> : null}
          {job.enrichmentError ? <InlineNotice variant="error">{job.enrichmentError}</InlineNotice> : null}
          {actionError ? <InlineNotice variant="error">{actionError}</InlineNotice> : null}
          {error ? <InlineNotice variant="warning">{error}</InlineNotice> : null}
          {failedChildren.length > 0 ? (
            <InlineNotice variant="warning" title="Partial batch detected">
              {failedChildren.length} file{failedChildren.length === 1 ? "" : "s"} failed during deterministic analysis.
              {job.completedChildren > 0
                ? " AI summary and sandbox enrichment will use only the completed files from this total job."
                : " No enrichment can run until at least one child analysis job completes successfully."}
              {failedChildNames.length ? ` Failed files: ${failedChildNames.join(", ")}.` : ""}
            </InlineNotice>
          ) : null}
          {!job.deterministicComplete ? (
            <InlineNotice variant="info" title="Enrichment locked">
              The AI summary and sandbox trigger becomes available after the deterministic child-file pass completes.
            </InlineNotice>
          ) : null}
          <InlineNotice variant="info" title="Batch-level summary">
            Use the batch summary action on this page to review one parent summary for the whole total job across {formatNumber(job.fileCount, 0)} child file{job.fileCount === 1 ? "" : "s"}, instead of opening child-file reports one by one.
          </InlineNotice>
        </div>
      </SectionCard>

      <SectionCard
        title="Files In This Total Job"
        subtitle="Review every child analysis job created from this batch run."
      >
        {!job.children.length ? (
          <EmptyState title="No child files" description="This total job does not contain any child analysis jobs." />
        ) : (
          <div className="overflow-hidden rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Filename</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Phase</TableHead>
                  <TableHead>Progress</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Runtime (s)</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {job.children.map((child) => (
                  <TableRow key={child.analysisJobId}>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <span className="text-sm">{child.filename}</span>
                        <span className="font-mono text-xs text-muted-foreground">{child.analysisJobId}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <StatusBadge value={child.status} />
                    </TableCell>
                    <TableCell>{formatPhaseLabel(child.currentPhase)}</TableCell>
                    <TableCell>{formatPercent(child.progress)}</TableCell>
                    <TableCell>
                      {child.riskLevel ? <StatusBadge value={child.riskLevel} /> : <span className="text-muted-foreground">N/A</span>}
                    </TableCell>
                    <TableCell>
                      {child.confidenceScore === null ? "N/A" : formatNumber(child.confidenceScore, 3)}
                    </TableCell>
                    <TableCell>
                      {child.runtimeSecondsTotal === null ? "N/A" : formatNumber(child.runtimeSecondsTotal, 3)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild size="sm" variant="ghost">
                        <Link href={`/analysis/${encodeURIComponent(child.analysisJobId)}`}>Open</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      <section id="batch-summary" className="scroll-mt-24">
        <ArtifactPanel
          title="Batch Summary Markdown"
          subtitle="Parent-level markdown summary for the whole total job, built from all completed child-file analysis records."
          copyValue={artifacts.summaryMarkdown ?? undefined}
          copyLabel="Copy summary markdown"
        >
          {artifactLoading ? (
            <p className="text-sm text-muted-foreground">Loading enrichment artifacts...</p>
          ) : artifacts.summaryMarkdown ? (
            <pre className="overflow-x-auto whitespace-pre-wrap text-sm leading-6 text-foreground/90">
              {artifacts.summaryMarkdown}
            </pre>
          ) : (
            <p className="text-sm text-muted-foreground">
              {job.enrichmentStatus === "completed"
                ? "Markdown summary not available."
                : "Trigger AI summary and sandbox to populate one parent-level batch summary for this total job."}
            </p>
          )}
        </ArtifactPanel>
      </section>

      {dedupeInfo ? (
        <SectionCard
          title="Dedupe Summary"
          subtitle="Parent enrichment removes duplicate PCAPs before AI summary and sandbox analysis."
        >
          <div className="flex flex-col gap-4">
            <KeyValueGrid
              items={[
                { label: "Submitted Records", value: formatNumber(dedupeInfo.inputRecordCount, 0) },
                { label: "Unique Records Used", value: formatNumber(dedupeInfo.uniqueRecordCount, 0) },
                { label: "Duplicates Removed", value: formatNumber(dedupeInfo.duplicateRecordCount, 0) },
                { label: "Strategy", value: dedupeInfo.strategy ?? "N/A" },
              ]}
            />
            {dedupeInfo.duplicateRecordCount > 0 ? (
              <InlineNotice variant="info" title="Duplicate PCAPs skipped">
                {dedupeInfo.duplicateRecordCount} duplicate file{dedupeInfo.duplicateRecordCount === 1 ? "" : "s"} were removed before AI and sandbox processing.
              </InlineNotice>
            ) : (
              <InlineNotice variant="info" title="No duplicates removed">
                All submitted completed PCAPs were treated as unique inputs for enrichment.
              </InlineNotice>
            )}
            {dedupeInfo.duplicatesRemoved.length ? (
              <div className="rounded-lg border border-border/70 bg-background/40 p-3">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Removed Duplicates</p>
                <ul className="mt-3 flex flex-col gap-2 text-sm text-foreground/85">
                  {dedupeInfo.duplicatesRemoved.map((entry, index) => (
                    <li key={`${entry.dedupeKey ?? "dedupe"}-${index}`} className="rounded-md border border-border/60 bg-background/30 px-3 py-2">
                      <div>{entry.file ?? "Unknown file"}</div>
                      {entry.path ? <div className="font-mono text-xs text-muted-foreground">{entry.path}</div> : null}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        </SectionCard>
      ) : null}

      <ArtifactPanel
        title="Batch Summary JSON"
        subtitle="Aggregate parent-level summary payload built from the completed files in this total job."
        copyValue={artifacts.summaryJson ? JSON.stringify(artifacts.summaryJson, null, 2) : undefined}
        copyLabel="Copy summary JSON"
      >
        {artifactLoading ? (
          <p className="text-sm text-muted-foreground">Loading enrichment artifacts...</p>
        ) : artifacts.summaryJson ? (
          <pre className="overflow-x-auto text-xs leading-6 text-foreground/90">
            {JSON.stringify(artifacts.summaryJson, null, 2)}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">No batch summary JSON available yet.</p>
        )}
      </ArtifactPanel>

      <ArtifactPanel
        title="Sandbox Output"
        subtitle="Sandbox-oriented enrichment results persisted at the total-job level."
        copyValue={artifacts.sandbox ? JSON.stringify(artifacts.sandbox, null, 2) : undefined}
        copyLabel="Copy sandbox JSON"
      >
        {artifactLoading ? (
          <p className="text-sm text-muted-foreground">Loading enrichment artifacts...</p>
        ) : artifacts.sandbox ? (
          <pre className="overflow-x-auto text-xs leading-6 text-foreground/90">
            {JSON.stringify(artifacts.sandbox, null, 2)}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">No sandbox output available yet.</p>
        )}
      </ArtifactPanel>

      {artifactError ? <InlineNotice variant="error">{artifactError}</InlineNotice> : null}
    </div>
  )
}
