"use client"

import Link from "next/link"
import { useCallback, useState } from "react"
import { useParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { CopyButton } from "@/components/common/copy-button"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { SectionCard } from "@/components/common/section-card"
import { useArtifact } from "@/hooks/use-artifact"
import { getMetrics, getReportJson, getReportMarkdown } from "@/lib/api/analysis"
import { adaptRunMetrics } from "@/lib/adapters/analysis"
import { formatNumber, titleCase } from "@/lib/format"

type RawTab = "report" | "markdown" | "metrics"

export default function AnalysisRawPage() {
  const params = useParams<{ jobId: string }>()
  const jobId = decodeURIComponent(params.jobId)
  const [tab, setTab] = useState<RawTab>("report")

  const reportState = useArtifact(
    useCallback(() => getReportJson(jobId), [jobId]),
    [jobId]
  )

  const markdownState = useArtifact(
    useCallback(async () => {
      const payload = await getReportMarkdown(jobId)
      return payload.markdown
    }, [jobId]),
    [jobId]
  )

  const metricsState = useArtifact(
    useCallback(async () => {
      const payload = await getMetrics(jobId)
      return adaptRunMetrics(payload)
    }, [jobId]),
    [jobId]
  )

  function renderReportTab() {
    if (reportState.loading && !reportState.data) {
      return <LoadingState title="Loading report.json" />
    }
    if (reportState.notReady && !reportState.data) {
      return (
        <EmptyState
          title="report.json not ready"
          description="The job may still be running. Retry after a few seconds."
        />
      )
    }
    if (!reportState.data && reportState.error) {
      return (
        <ErrorState
          title="Unable to load report.json"
          description={reportState.error}
          onRetry={() => void reportState.reload()}
        />
      )
    }
    if (!reportState.data) {
      return <EmptyState title="No report.json data" />
    }

    const text = JSON.stringify(reportState.data, null, 2)
    return (
      <SectionCard title="report.json" actions={<CopyButton value={text} label="Copy JSON" />}>
        <pre className="max-h-[70vh] overflow-auto rounded-lg border border-border bg-background/40 p-3 text-xs">
          {text}
        </pre>
      </SectionCard>
    )
  }

  function renderMarkdownTab() {
    if (markdownState.loading && !markdownState.data) {
      return <LoadingState title="Loading report.md" />
    }
    if (markdownState.notReady && !markdownState.data) {
      return (
        <EmptyState
          title="report.md not ready"
          description="The job may still be running. Retry after a few seconds."
        />
      )
    }
    if (!markdownState.data && markdownState.error) {
      return (
        <ErrorState
          title="Unable to load report.md"
          description={markdownState.error}
          onRetry={() => void markdownState.reload()}
        />
      )
    }
    if (!markdownState.data) {
      return <EmptyState title="No report.md data" />
    }

    const markdown = markdownState.data
    return (
      <SectionCard
        title="report.md"
        actions={<CopyButton value={markdown} label="Copy Markdown" />}
      >
        <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap rounded-lg border border-border bg-background/40 p-3 text-sm">
          {markdown || "No markdown content."}
        </pre>
      </SectionCard>
    )
  }

  function renderMetricsTab() {
    if (metricsState.loading && !metricsState.data) {
      return <LoadingState title="Loading metrics" />
    }
    if (metricsState.notReady && !metricsState.data) {
      return (
        <EmptyState
          title="metrics not ready"
          description="The job may still be running. Retry after a few seconds."
        />
      )
    }
    if (!metricsState.data && metricsState.error) {
      return (
        <ErrorState
          title="Unable to load metrics"
          description={metricsState.error}
          onRetry={() => void metricsState.reload()}
        />
      )
    }
    if (!metricsState.data) {
      return <EmptyState title="No metrics data" />
    }

    const metrics = metricsState.data
    const metricsJson = JSON.stringify(metrics, null, 2)

    return (
      <div className="space-y-4">
        <SectionCard title="metrics" actions={<CopyButton value={metricsJson} label="Copy Metrics" />}>
          <KeyValueGrid
            items={[
              { label: "Status", value: metrics.status },
              { label: "Runtime (s)", value: formatNumber(metrics.runtimeSecondsTotal, 3) },
              {
                label: "CPU Peak (%)",
                value: metrics.cpuPercentPeak === null ? "N/A" : formatNumber(metrics.cpuPercentPeak, 2),
              },
              {
                label: "RAM Peak (MB)",
                value: metrics.ramMbPeak === null ? "N/A" : formatNumber(metrics.ramMbPeak, 2),
              },
              { label: "LLM Tokens In", value: formatNumber(metrics.llmTokensIn, 0) },
              { label: "LLM Tokens Out", value: formatNumber(metrics.llmTokensOut, 0) },
              { label: "Compute Cost", value: `$${formatNumber(metrics.costCompute, 6)}` },
              { label: "LLM Cost", value: `$${formatNumber(metrics.costLlm, 6)}` },
              { label: "Storage Cost", value: `$${formatNumber(metrics.costStorage, 6)}` },
              {
                label: "Estimated Total Cost",
                value: `$${formatNumber(metrics.estimatedCostTotal, 6)}`,
              },
            ]}
          />
        </SectionCard>

        <SectionCard title="Phase Timings">
          <div className="space-y-2">
            {Object.entries(metrics.phaseTimingsSeconds).map(([phase, value]) => (
              <div
                key={phase}
                className="flex items-center justify-between rounded-md border border-border bg-background/40 px-3 py-2 text-sm"
              >
                <span>{titleCase(phase)}</span>
                <span>{formatNumber(value, 3)} s</span>
              </div>
            ))}
            {!Object.keys(metrics.phaseTimingsSeconds).length ? (
              <p className="text-sm text-muted-foreground">No phase timing data available.</p>
            ) : null}
          </div>
        </SectionCard>

        <SectionCard title="Raw metrics JSON">
          <pre className="max-h-[60vh] overflow-auto rounded-lg border border-border bg-background/40 p-3 text-xs">
            {metricsJson}
          </pre>
        </SectionCard>
      </div>
    )
  }

  function renderBody() {
    if (tab === "report") {
      return renderReportTab()
    }
    if (tab === "markdown") {
      return renderMarkdownTab()
    }
    return renderMetricsTab()
  }

  return (
    <div className="space-y-6">
      <SectionCard
        title="Raw Artifacts"
        subtitle={`Job ${jobId}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link href={`/analysis/${jobId}`}>Back to Job</Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link href={`/analysis/${jobId}/report`}>Open Report View</Link>
            </Button>
          </div>
        }
      >
        <div className="flex flex-wrap gap-2">
          {([
            ["report", "report.json"],
            ["markdown", "report.md"],
            ["metrics", "metrics"],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              type="button"
              onClick={() => setTab(key)}
              className={`rounded-md border px-3 py-1.5 text-sm transition ${
                tab === key
                  ? "border-primary/40 bg-primary/10"
                  : "border-border text-muted-foreground hover:bg-muted"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </SectionCard>

      {renderBody()}
    </div>
  )
}
