"use client"

import Link from "next/link"
import { useMemo, useState } from "react"

import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { InlineNotice } from "@/components/common/inline-notice"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
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
import { triggerTotalJobEnrichment } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import { useTotalJobs } from "@/hooks/use-total-jobs"
import { formatDateTime, formatNumber, formatPercent, formatPhaseLabel } from "@/lib/format"

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

export default function TotalJobsPage() {
  const { jobs, loading, error, refresh } = useTotalJobs()
  const [search, setSearch] = useState("")
  const [statusFilter, setStatusFilter] = useState("all")
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

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

  const canRunEnrichment = (enrichmentStatus: string, deterministicComplete: boolean) =>
    deterministicComplete && enrichmentStatus !== "running"

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
            <Button asChild>
              <Link href="/analysis/new">Start Batch Analysis</Link>
            </Button>
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
          <Button type="button" variant="outline" onClick={() => void refresh()}>
            Refresh
          </Button>
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
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={
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
    </div>
  )
}
