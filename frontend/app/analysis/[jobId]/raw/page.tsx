"use client"

import Link from "next/link"
import { useCallback, useState } from "react"
import { useParams, useRouter } from "next/navigation"

import { ArtifactPanel } from "@/components/common/artifact-panel"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { InlineNotice } from "@/components/common/inline-notice"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { SectionCard } from "@/components/common/section-card"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useArtifact } from "@/hooks/use-artifact"
import { useJobStatus } from "@/hooks/use-job-status"
import {
  getGuardrailAudit,
  getMetrics,
  getReportJson,
  getReportMarkdown,
} from "@/lib/api/analysis"
import { adaptGuardrailAudit, adaptRunMetrics } from "@/lib/adapters/analysis"
import { formatNumber, titleCase } from "@/lib/format"

const rowClassName = "flex items-center justify-between rounded-md border border-border/70 bg-background/40 px-3 py-2 text-sm"

type RawTab = "report" | "markdown" | "metrics" | "guardrails"

function NotReadyState({
  title,
  description,
  onRetry,
  onRefreshJob,
}: {
  title: string
  description: string
  onRetry: () => void
  onRefreshJob: () => void
}) {
  return (
    <EmptyState
      title={title}
      description={description}
      action={
        <div className="flex items-center gap-2">
          <Button type="button" variant="outline" size="sm" onClick={onRetry}>
            Retry Now
          </Button>
          <Button type="button" variant="ghost" size="sm" onClick={onRefreshJob}>
            Refresh Job Status
          </Button>
        </div>
      }
    />
  )
}

export default function AnalysisRawPage() {
  const params = useParams<{ jobId: string }>()
  const jobId = decodeURIComponent(params.jobId)
  const [tab, setTab] = useState<RawTab>("report")
  const router = useRouter()
  const { job, refresh, isPolling } = useJobStatus(jobId)

  const canNavigateGroup =
    job?.groupId &&
    typeof job.groupIndex === "number" &&
    typeof job.groupTotal === "number" &&
    job.groupTotal > 1

  const hasPrev = canNavigateGroup && (job?.groupIndex ?? 0) > 0
  const hasNext =
    canNavigateGroup &&
    job &&
    job.groupIndex !== null &&
    job.groupTotal !== null &&
    job.groupIndex < job.groupTotal - 1

  const handlePrev = () => {
    if (!job || !hasPrev || job.groupId === null || job.groupIndex === null) return
    const targetId = `${job.groupId}_${job.groupIndex - 1}`
    router.push(`/analysis/${encodeURIComponent(targetId)}/raw`)
  }

  const handleNext = () => {
    if (!job || !hasNext || job.groupId === null || job.groupIndex === null) return
    const targetId = `${job.groupId}_${job.groupIndex + 1}`
    router.push(`/analysis/${encodeURIComponent(targetId)}/raw`)
  }

  const reportState = useArtifact(useCallback(() => getReportJson(jobId), [jobId]), [jobId], {
    pollWhileNotReady: isPolling,
  })

  const markdownState = useArtifact(
    useCallback(async () => {
      const payload = await getReportMarkdown(jobId)
      return payload.markdown
    }, [jobId]),
    [jobId],
    { pollWhileNotReady: isPolling }
  )

  const metricsState = useArtifact(
    useCallback(async () => {
      const payload = await getMetrics(jobId)
      return adaptRunMetrics(payload)
    }, [jobId]),
    [jobId],
    { pollWhileNotReady: isPolling }
  )

  const guardrailAuditState = useArtifact(
    useCallback(async () => {
      const payload = await getGuardrailAudit(jobId)
      return adaptGuardrailAudit(payload)
    }, [jobId]),
    [jobId],
    { pollWhileNotReady: isPolling }
  )

  return (
    <Tabs
      value={tab}
      onValueChange={(value) => setTab(value as RawTab)}
      className="flex flex-col gap-6"
    >
      {job?.status !== "completed" ? (
        <InlineNotice variant="warning" title="Artifacts Pending">
          Raw artifacts are still being generated. The page is polling while the job remains queued or running.
        </InlineNotice>
      ) : null}

      <SectionCard
        title="Raw Artifacts"
        subtitle={`Job ${jobId}`}
        actions={
          <div className="flex items-center gap-2">
            {canNavigateGroup && job?.groupTotal !== null ? (
              <>
                <Button variant="outline" size="sm" disabled={!hasPrev} onClick={handlePrev}>
                  Previous
                </Button>
                <Button variant="outline" size="sm" disabled={!hasNext} onClick={handleNext}>
                  Next
                </Button>
                <span className="text-xs text-muted-foreground">
                  Batch: {job.groupIndex !== null ? job.groupIndex + 1 : "?"}/{job.groupTotal}
                </span>
              </>
            ) : null}
            <Button variant="outline" size="sm" asChild>
              <Link href={`/analysis/${jobId}`}>Back to Job</Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link href={`/analysis/${jobId}/report`}>Open Report View</Link>
            </Button>
          </div>
        }
      >
        <TabsList variant="line" className="flex h-auto flex-wrap items-center gap-2 p-0">
          <TabsTrigger value="report" className="h-8 flex-none rounded-md border border-border px-3">
            report.json
          </TabsTrigger>
          <TabsTrigger value="markdown" className="h-8 flex-none rounded-md border border-border px-3">
            report.md
          </TabsTrigger>
          <TabsTrigger value="metrics" className="h-8 flex-none rounded-md border border-border px-3">
            metrics
          </TabsTrigger>
          <TabsTrigger value="guardrails" className="h-8 flex-none rounded-md border border-border px-3">
            guardrail_audit.json
          </TabsTrigger>
        </TabsList>
      </SectionCard>

      <TabsContent value="report">
        {reportState.loading && !reportState.data ? (
          <LoadingState title="Loading report.json" />
        ) : reportState.notReady && !reportState.data ? (
          <NotReadyState
            title="report.json not ready"
            description="The job may still be running."
            onRetry={() => void reportState.reload()}
            onRefreshJob={() => void refresh()}
          />
        ) : !reportState.data && reportState.error ? (
          <ErrorState
            title="Unable to load report.json"
            description={reportState.error}
            onRetry={() => void reportState.reload()}
          />
        ) : !reportState.data ? (
          <EmptyState title="No report.json data" />
        ) : (
          <ArtifactPanel
            title="report.json"
            copyValue={JSON.stringify(reportState.data, null, 2)}
            copyLabel="Copy JSON"
          >
            <pre className="max-h-[70vh] overflow-auto text-xs">
              {JSON.stringify(reportState.data, null, 2)}
            </pre>
          </ArtifactPanel>
        )}
      </TabsContent>

      <TabsContent value="markdown">
        {markdownState.loading && !markdownState.data ? (
          <LoadingState title="Loading report.md" />
        ) : markdownState.notReady && !markdownState.data ? (
          <NotReadyState
            title="report.md not ready"
            description="The job may still be running."
            onRetry={() => void markdownState.reload()}
            onRefreshJob={() => void refresh()}
          />
        ) : !markdownState.data && markdownState.error ? (
          <ErrorState
            title="Unable to load report.md"
            description={markdownState.error}
            onRetry={() => void markdownState.reload()}
          />
        ) : !markdownState.data ? (
          <EmptyState title="No report.md data" />
        ) : (
          <ArtifactPanel title="report.md" copyValue={markdownState.data} copyLabel="Copy Markdown">
            <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap text-sm">
              {markdownState.data || "No markdown content."}
            </pre>
          </ArtifactPanel>
        )}
      </TabsContent>

      <TabsContent value="metrics">
        {metricsState.loading && !metricsState.data ? (
          <LoadingState title="Loading metrics" />
        ) : metricsState.notReady && !metricsState.data ? (
          <NotReadyState
            title="metrics not ready"
            description="The job may still be running."
            onRetry={() => void metricsState.reload()}
            onRefreshJob={() => void refresh()}
          />
        ) : !metricsState.data && metricsState.error ? (
          <ErrorState
            title="Unable to load metrics"
            description={metricsState.error}
            onRetry={() => void metricsState.reload()}
          />
        ) : !metricsState.data ? (
          <EmptyState title="No metrics data" />
        ) : (
          <div className="flex flex-col gap-4">
            <SectionCard
              title="metrics"
              actions={
                <Button variant="outline" size="sm" onClick={() => void navigator.clipboard.writeText(JSON.stringify(metricsState.data, null, 2))}>
                  Copy Metrics
                </Button>
              }
            >
              <KeyValueGrid
                items={[
                  { label: "Status", value: metricsState.data.status },
                  {
                    label: "Runtime (s)",
                    value: formatNumber(metricsState.data.runtimeSecondsTotal, 3),
                  },
                  { label: "Provider", value: metricsState.data.provider },
                  { label: "Model", value: metricsState.data.model },
                  { label: "Fallback Used", value: metricsState.data.fallbackUsed ? "Yes" : "No" },
                  {
                    label: "CPU Peak (%)",
                    value:
                      metricsState.data.cpuPercentPeak === null
                        ? "N/A"
                        : formatNumber(metricsState.data.cpuPercentPeak, 2),
                  },
                  {
                    label: "RAM Peak (MB)",
                    value:
                      metricsState.data.ramMbPeak === null
                        ? "N/A"
                        : formatNumber(metricsState.data.ramMbPeak, 2),
                  },
                  { label: "LLM Tokens In", value: formatNumber(metricsState.data.llmTokensIn, 0) },
                  { label: "LLM Tokens Out", value: formatNumber(metricsState.data.llmTokensOut, 0) },
                  {
                    label: "Compute Cost",
                    value: `$${formatNumber(metricsState.data.costCompute, 6)}`,
                  },
                  { label: "LLM Cost", value: `$${formatNumber(metricsState.data.costLlm, 6)}` },
                  {
                    label: "Storage Cost",
                    value: `$${formatNumber(metricsState.data.costStorage, 6)}`,
                  },
                  {
                    label: "Estimated Total Cost",
                    value: `$${formatNumber(metricsState.data.estimatedCostTotal, 6)}`,
                  },
                ]}
              />
            </SectionCard>

            <SectionCard title="Artifact Sizes">
              <div className="flex flex-col gap-2">
                {Object.entries(metricsState.data.artifactBytes).map(([name, value]) => (
                  <div key={name} className={rowClassName}>
                    <span>{titleCase(name.replaceAll("_", " "))}</span>
                    <span>{formatNumber(value, 0)} bytes</span>
                  </div>
                ))}
                {!Object.keys(metricsState.data.artifactBytes).length ? (
                  <p className="text-sm text-muted-foreground">No artifact size data available.</p>
                ) : null}
              </div>
            </SectionCard>

            <ArtifactPanel
              title="Cost Assumptions"
              copyValue={JSON.stringify(metricsState.data.costAssumptions, null, 2)}
              copyLabel="Copy Cost Assumptions"
            >
              <pre className="max-h-[30vh] overflow-auto text-xs">
                {JSON.stringify(metricsState.data.costAssumptions, null, 2)}
              </pre>
            </ArtifactPanel>

            <SectionCard title="Phase Timings">
              <div className="flex flex-col gap-2">
                {Object.entries(metricsState.data.phaseTimingsSeconds).map(([phase, value]) => (
                  <div key={phase} className={rowClassName}>
                    <span>{titleCase(phase)}</span>
                    <span>{formatNumber(value, 3)} s</span>
                  </div>
                ))}
                {!Object.keys(metricsState.data.phaseTimingsSeconds).length ? (
                  <p className="text-sm text-muted-foreground">No phase timing data available.</p>
                ) : null}
              </div>
            </SectionCard>

            <ArtifactPanel
              title="Raw metrics JSON"
              copyValue={JSON.stringify(metricsState.data, null, 2)}
              copyLabel="Copy Metrics JSON"
            >
              <pre className="max-h-[60vh] overflow-auto text-xs">
                {JSON.stringify(metricsState.data, null, 2)}
              </pre>
            </ArtifactPanel>
          </div>
        )}
      </TabsContent>

      <TabsContent value="guardrails">
        {guardrailAuditState.loading && !guardrailAuditState.data ? (
          <LoadingState title="Loading guardrail audit" />
        ) : guardrailAuditState.notReady && !guardrailAuditState.data ? (
          <NotReadyState
            title="guardrail audit not ready"
            description="The job may still be running."
            onRetry={() => void guardrailAuditState.reload()}
            onRefreshJob={() => void refresh()}
          />
        ) : !guardrailAuditState.data && guardrailAuditState.error ? (
          <ErrorState
            title="Unable to load guardrail audit"
            description={guardrailAuditState.error}
            onRetry={() => void guardrailAuditState.reload()}
          />
        ) : !guardrailAuditState.data ? (
          <EmptyState title="No guardrail audit data" />
        ) : (
          <div className="flex flex-col gap-4">
            <SectionCard title="Guardrail Audit">
              <KeyValueGrid
                items={[
                  {
                    label: "Human Review Required",
                    value: guardrailAuditState.data.humanReviewRequired,
                  },
                  {
                    label: "Read Only Mode",
                    value: guardrailAuditState.data.readOnlyMode ? "Yes" : "No",
                  },
                  {
                    label: "Contradictions",
                    value: guardrailAuditState.data.contradictions.length
                      ? guardrailAuditState.data.contradictions.join(", ")
                      : "None",
                  },
                ]}
              />
            </SectionCard>

            <ArtifactPanel
              title="Claim Checks"
              copyValue={JSON.stringify(guardrailAuditState.data.claimChecks, null, 2)}
              copyLabel="Copy Claim Checks"
            >
              <pre className="max-h-[40vh] overflow-auto text-xs">
                {JSON.stringify(guardrailAuditState.data.claimChecks, null, 2)}
              </pre>
            </ArtifactPanel>

            <ArtifactPanel
              title="Raw guardrail audit JSON"
              copyValue={JSON.stringify(guardrailAuditState.data, null, 2)}
              copyLabel="Copy Audit JSON"
            >
              <pre className="max-h-[60vh] overflow-auto text-xs">
                {JSON.stringify(guardrailAuditState.data, null, 2)}
              </pre>
            </ArtifactPanel>
          </div>
        )}
      </TabsContent>
    </Tabs>
  )
}
