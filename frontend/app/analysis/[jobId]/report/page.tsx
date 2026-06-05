"use client"

import Link from "next/link"
import { useCallback } from "react"
import { useParams, useRouter } from "next/navigation"

import { BulletList } from "@/components/common/bullet-list"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { InlineNotice } from "@/components/common/inline-notice"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { useArtifact } from "@/hooks/use-artifact"
import { useJobStatus } from "@/hooks/use-job-status"
import { adaptForensicReport } from "@/lib/adapters/analysis"
import { getReportJson } from "@/lib/api/analysis"
import {
  formatBytes,
  formatDateTime,
  formatNumber,
} from "@/lib/format"

const sectionLinks = [
  { id: "summary", label: "Summary" },
  { id: "evidence", label: "Evidence" },
  { id: "timeline", label: "Timeline" },
  { id: "findings", label: "Findings" },
  { id: "mitre", label: "MITRE" },
  { id: "impact", label: "Impact" },
  { id: "recommendations", label: "Recommendations" },
  { id: "guardrails", label: "Guardrails" },
]

function InsetPanel({
  label,
  children,
}: {
  label?: string
  children: React.ReactNode
}) {
  return (
    <Card size="sm" className="border border-border/70 bg-background/40 ring-0">
      <CardContent className="pt-3">
        {label ? <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p> : null}
        <div className={label ? "mt-2" : undefined}>{children}</div>
      </CardContent>
    </Card>
  )
}

export default function AnalysisReportPage() {
  const params = useParams<{ jobId: string }>()
  const jobId = decodeURIComponent(params.jobId)
  const router = useRouter()
  const { job, error: jobError, refresh, isPolling } = useJobStatus(jobId)

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
    router.push(`/analysis/${encodeURIComponent(targetId)}/report`)
  }

  const handleNext = () => {
    if (!job || !hasNext || job.groupId === null || job.groupIndex === null) return
    const targetId = `${job.groupId}_${job.groupIndex + 1}`
    router.push(`/analysis/${encodeURIComponent(targetId)}/report`)
  }

  const loadReport = useCallback(async () => {
    const payload = await getReportJson(jobId)
    return adaptForensicReport(payload)
  }, [jobId])

  const reportState = useArtifact(loadReport, [loadReport], {
    pollWhileNotReady: isPolling || job?.status === "completed",
  })

  async function retryReport() {
    await refresh()
    await reportState.reload()
  }

  if (reportState.loading && !reportState.data) {
    return <LoadingState title="Loading report" description={`Job: ${jobId}`} />
  }

  if (reportState.notReady && !reportState.data) {
    return (
      <EmptyState
        title="Report not ready"
        description="The analysis job has not finished writing report.json yet."
        action={
          <div className="flex items-center gap-2">
            <Button type="button" variant="outline" size="sm" onClick={() => void retryReport()}>
              Retry Now
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={() => void refresh()}>
              Refresh Job Status
            </Button>
          </div>
        }
      />
    )
  }

  if (!reportState.data && reportState.error) {
    return (
      <ErrorState
        title="Unable to load report"
        description={reportState.error}
        onRetry={() => void retryReport()}
      />
    )
  }

  if (!reportState.data) {
    return <EmptyState title="No report data" description="No report payload was returned." />
  }

  const report = reportState.data

  return (
    <div className="flex flex-col gap-6">
      {job?.status !== "completed" ? (
        <InlineNotice variant="warning" title="Artifacts Pending">
          The report view is polling while the backend finishes the job. Current status: {job?.status ?? "unknown"}.
        </InlineNotice>
      ) : null}
      {jobError ? <InlineNotice variant="warning">{jobError}</InlineNotice> : null}

      <SectionCard
        title="Forensic Report"
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
              <Link href={`/analysis/${jobId}/raw`}>Open Raw</Link>
            </Button>
            <Button variant="outline" size="sm" onClick={() => void retryReport()}>
              Refresh
            </Button>
          </div>
        }
      >
        <nav className="flex flex-wrap gap-2">
          {sectionLinks.map((section) => (
            <Button key={section.id} asChild variant="outline" size="sm" className="h-7">
              <a href={`#${section.id}`}>{section.label}</a>
            </Button>
          ))}
        </nav>
      </SectionCard>

      <section id="summary">
        <SectionCard title="Summary">
          <div className="flex flex-col gap-4">
            <KeyValueGrid
              items={[
                { label: "Case ID", value: <code>{report.header.caseId}</code> },
                { label: "Timestamp", value: formatDateTime(report.header.timestamp) },
                { label: "Analyst Mode", value: report.header.analystMode },
                { label: "Data Sources", value: report.header.dataSources.join(", ") || "N/A" },
                { label: "Filename", value: report.header.metadata.filename ?? job?.metadata.filename ?? "N/A" },
                {
                  label: "File Size",
                  value: formatBytes(report.header.metadata.sizeBytes ?? job?.metadata.sizeBytes),
                },
                {
                  label: "Packets / Flows",
                  value:
                    report.header.metadata.packetCount === null && report.header.metadata.flowCount === null
                      ? job?.metadata.packetCount === null && job?.metadata.flowCount === null
                        ? "N/A"
                        : `${job?.metadata.packetCount ?? "?"} / ${job?.metadata.flowCount ?? "?"}`
                      : `${report.header.metadata.packetCount ?? "?"} / ${report.header.metadata.flowCount ?? "?"}`,
                },
                {
                  label: "Capture Window",
                  value:
                    report.header.metadata.captureStart && report.header.metadata.captureEnd
                      ? `${formatDateTime(report.header.metadata.captureStart)} -> ${formatDateTime(report.header.metadata.captureEnd)}`
                      : job?.metadata.captureStart && job.metadata.captureEnd
                        ? `${formatDateTime(job.metadata.captureStart)} -> ${formatDateTime(job.metadata.captureEnd)}`
                        : "N/A",
                },
              ]}
            />
            <InsetPanel label="Analyst Summary (Markdown)">
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap text-sm">
                {report.analystSummaryMarkdown || "No markdown summary available."}
              </pre>
            </InsetPanel>
          </div>
        </SectionCard>
      </section>

      <section id="evidence">
        <SectionCard title="Evidence">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Key Packets / Flows</p>
              <BulletList items={report.evidence.keyPacketsFlows} />
            </div>
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">IOC List</p>
              <BulletList items={report.evidence.iocList} />
            </div>
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Suspicious Sessions</p>
              <BulletList items={report.evidence.suspiciousSessions} />
            </div>
          </div>
        </SectionCard>
      </section>

      <section id="timeline">
        <SectionCard title="Timeline">
          <BulletList items={report.evidence.correlatedEventsTimeline} />
        </SectionCard>
      </section>

      <section id="findings">
        <SectionCard title="Findings">
          <div className="flex flex-col gap-4">
            <div className="grid gap-4 md:grid-cols-2">
              <KeyValueGrid
                items={[
                  { label: "Primary Finding", value: report.findings.primaryFinding },
                  {
                    label: "Confidence Score",
                    value: `${formatNumber(report.findings.confidenceScore, 3)} / 1.000`,
                  },
                ]}
              />
              <InsetPanel label="Checklist-Critical Blocks">
                <div className="flex flex-col gap-2 text-sm">
                  <p>
                    <span className="font-medium">Observation:</span> {report.findings.observation}
                  </p>
                  <p>
                    <span className="font-medium">Inference:</span> {report.findings.inference}
                  </p>
                  <p>
                    <span className="font-medium">Recommendation:</span> {report.findings.recommendation}
                  </p>
                </div>
              </InsetPanel>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="flex flex-col gap-2">
                <p className="text-sm font-medium">Supporting Evidence</p>
                <BulletList items={report.findings.supportingEvidence} />
              </div>
              <div className="flex flex-col gap-2">
                <p className="text-sm font-medium">Alternative Hypotheses</p>
                <BulletList items={report.findings.alternativeHypotheses} />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="flex flex-col gap-2">
                <p className="text-sm font-medium">Direct Evidence</p>
                <BulletList items={report.findings.directEvidence} />
              </div>
              <div className="flex flex-col gap-2">
                <p className="text-sm font-medium">Uncertainties</p>
                <BulletList items={report.findings.uncertainties} />
              </div>
            </div>
          </div>
        </SectionCard>
      </section>

      <section id="mitre">
        <SectionCard title="MITRE ATT&CK Mapping">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Mapped Techniques</p>
              <BulletList items={report.findings.mitreTechniques} />
            </div>
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Evidence Reference IDs</p>
              <BulletList items={report.findings.evidenceRefIds} />
            </div>
          </div>
        </SectionCard>
      </section>

      <section id="impact">
        <SectionCard title="Impact">
          <KeyValueGrid
            items={[
              { label: "Attack Type", value: report.impact.attackType },
              { label: "Risk Level", value: <StatusBadge value={report.impact.riskLevel} /> },
              { label: "Affected Assets", value: report.impact.affectedAssets.join(", ") || "N/A" },
            ]}
          />
        </SectionCard>
      </section>

      <section id="recommendations">
        <SectionCard title="Recommended Actions">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Immediate Containment</p>
              <BulletList items={report.recommendedActions.immediateContainment} />
            </div>
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Validation Steps</p>
              <BulletList items={report.recommendedActions.validationSteps} />
            </div>
            <div className="flex flex-col gap-2">
              <p className="text-sm font-medium">Long-Term Hardening</p>
              <BulletList items={report.recommendedActions.longerTermHardening} />
            </div>
          </div>
        </SectionCard>
      </section>

      <section id="guardrails">
        <SectionCard title="Guardrail Verification">
          <KeyValueGrid
            items={[
              {
                label: "Data Validity Check",
                value: <StatusBadge value={report.guardrailVerification.dataValidityCheck} />,
              },
              {
                label: "Tool Output Validation",
                value: <StatusBadge value={report.guardrailVerification.toolOutputValidation} />,
              },
              {
                label: "Human Review Required",
                value: <StatusBadge value={report.guardrailVerification.humanReviewRequired} />,
              },
            ]}
          />
        </SectionCard>
      </section>

      <SectionCard title="Evidence References">
        <div className="flex flex-col gap-3">
          {report.evidence.evidenceRefs.map((ref) => (
            <Card key={ref.refId} size="sm" className="border border-border/70 bg-background/40 ring-0">
              <CardContent className="pt-3 text-sm">
                <p className="font-medium">{ref.refId} - {ref.detector} - {ref.claim}</p>
                <p className="mt-2">{ref.summary}</p>
                <p className="mt-2 text-muted-foreground">Source: {ref.sourceFile}</p>
                <p className="mt-1 text-muted-foreground">Flow: {ref.flow || "N/A"}</p>
                <p className="mt-1 text-muted-foreground">
                  Frames: {ref.frameNumbers.length ? ref.frameNumbers.join(", ") : "No sampled frames"}
                </p>
                <p className="mt-1 break-all text-muted-foreground">
                  Filter: <code>{ref.wiresharkFilter || "N/A"}</code>
                </p>
              </CardContent>
            </Card>
          ))}
          {!report.evidence.evidenceRefs.length ? (
            <p className="text-sm text-muted-foreground">No evidence references available.</p>
          ) : null}
        </div>
      </SectionCard>
    </div>
  )
}
