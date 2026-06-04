"use client"

import Link from "next/link"
import { useCallback, useEffect, useMemo, useState } from "react"

import { ArtifactPanel } from "@/components/common/artifact-panel"
import { useAuth } from "@/components/providers/auth-provider"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { InlineNotice } from "@/components/common/inline-notice"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import {
  getAllTotalJobsSummaryJson,
  getAllTotalJobsSummaryMarkdown,
  getAllTotalJobsSummarySandbox,
  getAllTotalJobsSummaryStatus,
  triggerAllTotalJobsSummary,
  triggerTotalJobEnrichment,
} from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { useTotalJobs } from "@/hooks/use-total-jobs"
import { formatDateTime, formatNumber, formatPercent, formatPhaseLabel } from "@/lib/format"
import { canCreateAnalysis } from "@/lib/permissions"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function SummaryStat({
  label,
  value,
  hint,
}: {
  label: string
  value: string
  hint: string
}) {
  return (
    <div className="rounded-lg border border-border/70 bg-background/40 p-4">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
      <p className="mt-1 text-sm text-muted-foreground">{hint}</p>
    </div>
  )
}

type AllJobsSummaryStatus = {
  status: string
  progress: number
  error?: string | null
  generated_at?: string | null
  updated_at?: string | null
  source_total_job_count: number
  source_file_count: number
  record_count?: number | null
  unique_record_count?: number | null
  duplicate_record_count?: number | null
}

type AllJobsSummaryArtifacts = {
  summaryJson: unknown | null
  summaryMarkdown: string | null
  sandbox: unknown | null
}

const EMPTY_ALL_JOBS_ARTIFACTS: AllJobsSummaryArtifacts = {
  summaryJson: null,
  summaryMarkdown: null,
  sandbox: null,
}

export default function TotalJobsPage() {
  const { session } = useAuth()
  const mayCreateAnalysis = canCreateAnalysis(session?.organization.role)
  const { jobs, loading, error, refresh } = useTotalJobs()
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState("all")
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [allJobsSummaryStatus, setAllJobsSummaryStatus] = useState<AllJobsSummaryStatus | null>(null)
  const [allJobsSummaryArtifacts, setAllJobsSummaryArtifacts] = useState<AllJobsSummaryArtifacts>(
    EMPTY_ALL_JOBS_ARTIFACTS
  )
  const [allJobsSummaryLoading, setAllJobsSummaryLoading] = useState(true)
  const [allJobsSummaryActionLoading, setAllJobsSummaryActionLoading] = useState(false)
  const [allJobsSummaryError, setAllJobsSummaryError] = useState<string | null>(null)

  const filteredJobs = useMemo(() => {
    return jobs.filter((job) => {
      const matchesStatus = statusFilter === "all" || job.status.toLowerCase() === statusFilter
      if (!matchesStatus) {
        return false
      }

      if (!search.trim()) {
        return true
      }

      const needle = search.trim().toLowerCase()
      const childNames = job.children.map((child) => child.filename).join(" ")
      return [
        job.totalJobId,
        job.status,
        job.currentStage,
        job.enrichmentStatus,
        childNames,
      ].some((value) => value.toLowerCase().includes(needle))
    })
  }, [jobs, search, statusFilter])

  const summary = useMemo(() => {
    const totalFiles = jobs.reduce((sum, job) => sum + job.fileCount, 0)
    const deterministicReady = jobs.filter((job) => job.deterministicComplete).length
    const enrichmentReady = jobs.filter((job) => job.enrichmentStatus === "completed").length
    const active = jobs.filter((job) => job.status === "running" || job.status === "queued").length

    return {
      totalJobs: jobs.length,
      totalFiles,
      deterministicReady,
      enrichmentReady,
      active,
    }
  }, [jobs])

  const loadAllJobsSummary = useCallback(async () => {
    setAllJobsSummaryLoading(true)
    try {
      const status = await getAllTotalJobsSummaryStatus()
      setAllJobsSummaryStatus(status)

      if (status.status === "completed") {
        const [summaryJson, summaryMarkdown, sandbox] = await Promise.all([
          getAllTotalJobsSummaryJson(),
          getAllTotalJobsSummaryMarkdown(),
          getAllTotalJobsSummarySandbox(),
        ])
        setAllJobsSummaryArtifacts({
          summaryJson,
          summaryMarkdown: summaryMarkdown.markdown,
          sandbox,
        })
      } else {
        setAllJobsSummaryArtifacts(EMPTY_ALL_JOBS_ARTIFACTS)
      }

      setAllJobsSummaryError(null)
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Unable to load the all-scans summary."
      setAllJobsSummaryArtifacts(EMPTY_ALL_JOBS_ARTIFACTS)
      setAllJobsSummaryError(message)
    } finally {
      setAllJobsSummaryLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadAllJobsSummary()
  }, [loadAllJobsSummary])

  useEffect(() => {
    const currentStatus = allJobsSummaryStatus?.status
    if (currentStatus !== "queued" && currentStatus !== "running") {
      return
    }

    const intervalId = window.setInterval(() => {
      void loadAllJobsSummary()
    }, 5000)

    return () => {
      window.clearInterval(intervalId)
    }
  }, [allJobsSummaryStatus?.status, loadAllJobsSummary])

  const handleEnrichment = async (totalJobId: string) => {
    setActionLoadingId(totalJobId)
    try {
      await triggerTotalJobEnrichment(totalJobId)
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
      setActionLoadingId(null)
    }
  }

  const handleRefresh = async () => {
    await Promise.all([refresh(), loadAllJobsSummary()])
  }

  const handleAllJobsSummary = async () => {
    setAllJobsSummaryActionLoading(true)
    try {
      await triggerAllTotalJobsSummary()
      setAllJobsSummaryError(null)
      await loadAllJobsSummary()
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Unable to trigger the all-scans summary."
      setAllJobsSummaryError(message)
    } finally {
      setAllJobsSummaryActionLoading(false)
    }
  }

  const canRunEnrichment = (enrichmentStatus: string, deterministicComplete: boolean) =>
    deterministicComplete && enrichmentStatus !== "running"

  const canOpenSummary = (enrichmentStatus: string) => enrichmentStatus === "completed"

  const canRunAllJobsSummary =
    (allJobsSummaryStatus?.source_file_count ?? 0) > 0 &&
    allJobsSummaryStatus?.status !== "queued" &&
    allJobsSummaryStatus?.status !== "running"

  const canOpenAllJobsSummary = allJobsSummaryStatus?.status === "completed"

  const getEnrichmentButtonLabel = (enrichmentStatus: string, isLoading: boolean) => {
    if (isLoading) {
      return "Starting..."
    }
    if (enrichmentStatus === "running") {
      return "AI Running"
    }
    if (enrichmentStatus === "completed") {
      return "Re-run AI"
    }
    if (enrichmentStatus === "failed") {
      return "Retry AI"
    }
    return "Run AI"
  }

  const getAllJobsSummaryButtonLabel = (status: string | undefined, isLoading: boolean) => {
    if (isLoading) {
      return "Starting..."
    }
    if (status === "queued" || status === "running") {
      return "All-Scans Summary Running"
    }
    if (status === "completed") {
      return "Re-run All-Scans Summary"
    }
    if (status === "failed") {
      return "Retry All-Scans Summary"
    }
    return "Run All-Scans Summary"
  }

  if (loading && !jobs.length) {
    return (
      <div className="flex flex-col gap-6">
        <LoadingState
          title="Loading total jobs"
          description="Fetching batch runs and their child-file progress."
        />
      </div>
    )
  }

  if (error && !jobs.length) {
    return (
      <div className="flex flex-col gap-6">
        <ErrorState title="Unable to load total jobs" description={error} onRetry={() => void refresh()} />
      </div>
    )
  }

  if (!jobs.length) {
    return (
      <div className="flex flex-col gap-6">
        <EmptyState
          title="No total jobs yet"
          description="Submit one or more PCAP files to create a batch run and track the files under a parent job."
          action={
            mayCreateAnalysis ? (
              <Button asChild>
                <Link href="/analysis/new">Start Batch Analysis</Link>
              </Button>
            ) : undefined
          }
        />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Total Jobs"
        subtitle="Monitor batch-level progress, file counts, and delayed enrichment readiness."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {canOpenAllJobsSummary ? (
              <Button asChild type="button" variant="secondary">
                <a href="#all-scans-summary">Open All-Scans Summary</a>
              </Button>
            ) : (
              <Button type="button" variant="secondary" disabled>
                All-Scans Summary Pending
              </Button>
            )}
            <Button
              type="button"
              onClick={() => void handleAllJobsSummary()}
              disabled={!mayCreateAnalysis || !canRunAllJobsSummary || allJobsSummaryActionLoading}
            >
              {getAllJobsSummaryButtonLabel(allJobsSummaryStatus?.status, allJobsSummaryActionLoading)}
            </Button>
            <Button type="button" variant="outline" onClick={() => void handleRefresh()}>
              Refresh
            </Button>
          </div>
        }
      >
        <div className="flex flex-col gap-4">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <SummaryStat
              label="Total Jobs"
              value={formatNumber(summary.totalJobs, 0)}
              hint="Persisted parent runs."
            />
            <SummaryStat
              label="Total Files"
              value={formatNumber(summary.totalFiles, 0)}
              hint="All child PCAPs across batches."
            />
            <SummaryStat
              label="Active"
              value={formatNumber(summary.active, 0)}
              hint="Queued or running parent jobs."
            />
            <SummaryStat
              label="Ready For Enrichment"
              value={formatNumber(summary.deterministicReady, 0)}
              hint="Deterministic pass finished."
            />
            <SummaryStat
              label="Enriched"
              value={formatNumber(summary.enrichmentReady, 0)}
              hint="AI summary plus sandbox completed."
            />
          </div>

          <div className="flex flex-col gap-3 md:flex-row md:items-center">
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search total job ID, stage, enrichment, or filenames"
              className="md:max-w-sm"
            />
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="md:w-48">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {error ? <InlineNotice variant="error">{error}</InlineNotice> : null}
          {actionError ? <InlineNotice variant="error">{actionError}</InlineNotice> : null}
          <InlineNotice title="All-Scans Summary">
            Run one combined summary across all completed child scans from every total job. This is the parent-level
            answer for large split imports, so you do not need to open each total job just to summarize the full set.
          </InlineNotice>
          {allJobsSummaryError ? <InlineNotice variant="error">{allJobsSummaryError}</InlineNotice> : null}

          {!filteredJobs.length ? (
            <EmptyState
              title="No matching total jobs"
              description="Try a broader search or clear the active status filter."
              action={
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setSearch("")
                    setStatusFilter("all")
                  }}
                >
                  Clear Filters
                </Button>
              }
            />
          ) : (
            <div className="overflow-hidden rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Total Job</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Stage</TableHead>
                    <TableHead>Files</TableHead>
                    <TableHead>Workers</TableHead>
                    <TableHead>Children</TableHead>
                    <TableHead>Enrichment</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredJobs.map((job) => (
                    <TableRow key={job.totalJobId}>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <span className="font-mono text-xs text-foreground/80">{job.totalJobId}</span>
                          <span className="text-xs text-muted-foreground">
                            {job.children.slice(0, 2).map((child) => child.filename).join(", ")
                              || "No files"}
                            {job.children.length > 2 ? ` +${job.children.length - 2} more` : ""}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <StatusBadge value={job.status} />
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <span className="text-sm">{formatPhaseLabel(job.currentStage)}</span>
                          <span className="text-xs text-muted-foreground">{formatPercent(job.progress)}</span>
                        </div>
                      </TableCell>
                      <TableCell>{formatNumber(job.fileCount, 0)}</TableCell>
                      <TableCell>{formatNumber(job.workerCount, 0)}</TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <div>
                            <span className="text-sm text-foreground/80">
                              {formatNumber(job.completedChildren, 0)} complete
                            </span>
                            <span className="mx-1 text-muted-foreground">/</span>
                            <span className="text-sm text-foreground/80">{formatNumber(job.fileCount, 0)} total</span>
                          </div>
                          {job.failedChildren > 0 ? (
                            <span className="text-xs text-yellow-300">
                              Partial batch: {formatNumber(job.failedChildren, 0)} failed and will be skipped by AI.
                            </span>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <StatusBadge value={job.enrichmentStatus} />
                          <span className="text-xs text-muted-foreground">
                            {formatPercent(job.enrichmentProgress)}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {job.createdAt ? formatDateTime(job.createdAt) : "N/A"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          {canOpenSummary(job.enrichmentStatus) ? (
                            <Button asChild size="sm" variant="secondary">
                              <Link href={`/total-jobs/${encodeURIComponent(job.totalJobId)}#batch-summary`}>
                                Summary
                              </Link>
                            </Button>
                          ) : (
                            <Button type="button" size="sm" variant="secondary" disabled>
                              Summary
                            </Button>
                          )}
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={
                              !mayCreateAnalysis ||
                              !canRunEnrichment(job.enrichmentStatus, job.deterministicComplete) ||
                              actionLoadingId === job.totalJobId
                            }
                            onClick={() => void handleEnrichment(job.totalJobId)}
                          >
                            {getEnrichmentButtonLabel(
                              job.enrichmentStatus,
                              actionLoadingId === job.totalJobId
                            )}
                          </Button>
                          <Button asChild size="sm" variant="ghost">
                            <Link href={`/total-jobs/${encodeURIComponent(job.totalJobId)}`}>Open</Link>
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
      </SectionCard>

      <section id="all-scans-summary" className="scroll-mt-24">
        <ArtifactPanel
          title="All Completed Scans Summary Markdown"
          subtitle={`One combined summary across ${formatNumber(allJobsSummaryStatus?.source_file_count ?? 0, 0)} completed child files from ${formatNumber(allJobsSummaryStatus?.source_total_job_count ?? 0, 0)} total jobs.`}
          copyValue={allJobsSummaryArtifacts.summaryMarkdown ?? undefined}
          copyLabel="Copy all-scans summary markdown"
        >
          {allJobsSummaryLoading ? (
            <p className="text-sm text-muted-foreground">Loading combined total-jobs summary...</p>
          ) : allJobsSummaryArtifacts.summaryMarkdown ? (
            <pre className="overflow-x-auto whitespace-pre-wrap text-sm leading-6 text-foreground/90">
              {allJobsSummaryArtifacts.summaryMarkdown}
            </pre>
          ) : (
            <p className="text-sm text-muted-foreground">
              {(allJobsSummaryStatus?.status ?? "not_started") === "completed"
                ? "Combined summary markdown is not available."
                : "Run the all-scans summary to analyze every completed child scan across all total jobs in one report."}
            </p>
          )}
        </ArtifactPanel>
      </section>

      <ArtifactPanel
        title="All Completed Scans Summary JSON"
        subtitle="Combined structured summary built from all completed child scans across total jobs."
        copyValue={
          allJobsSummaryArtifacts.summaryJson
            ? JSON.stringify(allJobsSummaryArtifacts.summaryJson, null, 2)
            : undefined
        }
        copyLabel="Copy all-scans summary JSON"
      >
        {allJobsSummaryLoading ? (
          <p className="text-sm text-muted-foreground">Loading combined total-jobs summary...</p>
        ) : allJobsSummaryArtifacts.summaryJson ? (
          <pre className="overflow-x-auto text-xs leading-6 text-foreground/90">
            {JSON.stringify(allJobsSummaryArtifacts.summaryJson, null, 2)}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">No combined all-scans summary JSON available yet.</p>
        )}
      </ArtifactPanel>

      <ArtifactPanel
        title="All Completed Scans Sandbox Output"
        subtitle="Combined sandbox-oriented enrichment view for all completed child scans across total jobs."
        copyValue={
          allJobsSummaryArtifacts.sandbox
            ? JSON.stringify(allJobsSummaryArtifacts.sandbox, null, 2)
            : undefined
        }
        copyLabel="Copy all-scans sandbox JSON"
      >
        {allJobsSummaryLoading ? (
          <p className="text-sm text-muted-foreground">Loading combined total-jobs summary...</p>
        ) : allJobsSummaryArtifacts.sandbox ? (
          <pre className="overflow-x-auto text-xs leading-6 text-foreground/90">
            {JSON.stringify(allJobsSummaryArtifacts.sandbox, null, 2)}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">No combined sandbox output available yet.</p>
        )}
      </ArtifactPanel>
    </div>
  )
}
