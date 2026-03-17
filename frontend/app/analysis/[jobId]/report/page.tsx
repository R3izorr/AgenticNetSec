"use client"

import Link from "next/link"
import { useCallback } from "react"
import { useParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { BulletList } from "@/components/common/bullet-list"
import { EmptyState, ErrorState, LoadingState } from "@/components/common/page-state"
import { KeyValueGrid } from "@/components/common/key-value-grid"
import { SectionCard } from "@/components/common/section-card"
import { StatusBadge } from "@/components/common/status-badge"
import { useArtifact } from "@/hooks/use-artifact"
import { getReportJson } from "@/lib/api/analysis"
import { adaptForensicReport } from "@/lib/adapters/analysis"
import { formatDateTime, formatNumber } from "@/lib/format"

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

export default function AnalysisReportPage() {
  const params = useParams<{ jobId: string }>()
  const jobId = decodeURIComponent(params.jobId)

  const loadReport = useCallback(async () => {
    const payload = await getReportJson(jobId)
    return adaptForensicReport(payload)
  }, [jobId])

  const reportState = useArtifact(loadReport, [loadReport])

  if (reportState.loading && !reportState.data) {
    return <LoadingState title="Loading report" description={`Job: ${jobId}`} />
  }

  if (reportState.notReady && !reportState.data) {
    return (
      <EmptyState
        title="Report not ready"
        description="The analysis job has not finished writing report.json yet."
      />
    )
  }

  if (!reportState.data && reportState.error) {
    return (
      <ErrorState
        title="Unable to load report"
        description={reportState.error}
        onRetry={() => void reportState.reload()}
      />
    )
  }

  if (!reportState.data) {
    return <EmptyState title="No report data" description="No report payload was returned." />
  }

  const report = reportState.data

  return (
    <div className="space-y-6">
      <SectionCard
        title="Forensic Report"
        subtitle={`Job ${jobId}`}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link href={`/analysis/${jobId}`}>Back to Job</Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link href={`/analysis/${jobId}/raw`}>Open Raw</Link>
            </Button>
          </div>
        }
      >
        <nav className="flex flex-wrap gap-2">
          {sectionLinks.map((section) => (
            <a
              key={section.id}
              href={`#${section.id}`}
              className="rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted"
            >
              {section.label}
            </a>
          ))}
        </nav>
      </SectionCard>

      <section id="summary">
        <SectionCard title="Summary">
          <KeyValueGrid
            items={[
              { label: "Case ID", value: <code>{report.header.caseId}</code> },
              { label: "Timestamp", value: formatDateTime(report.header.timestamp) },
              { label: "Analyst Mode", value: report.header.analystMode },
              { label: "Data Sources", value: report.header.dataSources.join(", ") || "N/A" },
            ]}
          />
          <div className="mt-4 rounded-lg border border-border bg-background/40 p-3">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Analyst Summary (Markdown)</p>
            <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap text-sm">
              {report.analystSummaryMarkdown || "No markdown summary available."}
            </pre>
          </div>
        </SectionCard>
      </section>

      <section id="evidence">
        <SectionCard title="Evidence">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="mb-2 text-sm font-medium">Key Packets / Flows</p>
              <BulletList items={report.evidence.keyPacketsFlows} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">IOC List</p>
              <BulletList items={report.evidence.iocList} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">Suspicious Sessions</p>
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
            <div className="rounded-lg border border-border bg-background/40 p-3">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Checklist-Critical Blocks</p>
              <p className="mt-2 text-sm"><span className="font-medium">Observation:</span> {report.findings.observation}</p>
              <p className="mt-2 text-sm"><span className="font-medium">Inference:</span> {report.findings.inference}</p>
              <p className="mt-2 text-sm"><span className="font-medium">Recommendation:</span> {report.findings.recommendation}</p>
            </div>
          </div>

          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <div>
              <p className="mb-2 text-sm font-medium">Supporting Evidence</p>
              <BulletList items={report.findings.supportingEvidence} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">Alternative Hypotheses</p>
              <BulletList items={report.findings.alternativeHypotheses} />
            </div>
          </div>

          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <div>
              <p className="mb-2 text-sm font-medium">Direct Evidence</p>
              <BulletList items={report.findings.directEvidence} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">Uncertainties</p>
              <BulletList items={report.findings.uncertainties} />
            </div>
          </div>
        </SectionCard>
      </section>

      <section id="mitre">
        <SectionCard title="MITRE ATT&CK Mapping">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <p className="mb-2 text-sm font-medium">Mapped Techniques</p>
              <BulletList items={report.findings.mitreTechniques} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">Evidence Reference IDs</p>
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
            <div>
              <p className="mb-2 text-sm font-medium">Immediate Containment</p>
              <BulletList items={report.recommendedActions.immediateContainment} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">Validation Steps</p>
              <BulletList items={report.recommendedActions.validationSteps} />
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">Long-Term Hardening</p>
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
        <div className="space-y-3">
          {report.evidence.evidenceRefs.map((ref) => (
            <div key={ref.refId} className="rounded-lg border border-border bg-background/40 p-3 text-sm">
              <p className="font-medium">{ref.refId} · {ref.detector} · {ref.claim}</p>
              <p className="mt-2">{ref.summary}</p>
              <p className="mt-2 text-muted-foreground">Source: {ref.sourceFile}</p>
              <p className="mt-1 text-muted-foreground">Flow: {ref.flow || "N/A"}</p>
              <p className="mt-1 text-muted-foreground">
                Frames: {ref.frameNumbers.length ? ref.frameNumbers.join(", ") : "No sampled frames"}
              </p>
              <p className="mt-1 break-all text-muted-foreground">
                Filter: <code>{ref.wiresharkFilter || "N/A"}</code>
              </p>
            </div>
          ))}
          {!report.evidence.evidenceRefs.length ? (
            <p className="text-sm text-muted-foreground">No evidence references available.</p>
          ) : null}
        </div>
      </SectionCard>
    </div>
  )
}
