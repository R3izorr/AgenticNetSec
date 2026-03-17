export type JobTerminalStatus = "completed" | "failed"

export interface JobStatus {
  analysisJobId: string
  status: string
  currentPhase: string
  progress: number
  guardrailState: string
  error: string | null
}

export interface ReportHeader {
  caseId: string
  timestamp: string
  analystMode: string
  dataSources: string[]
}

export interface ReportEvidence {
  keyPacketsFlows: string[]
  iocList: string[]
  suspiciousSessions: string[]
  correlatedEventsTimeline: string[]
  evidenceRefs: EvidenceRef[]
}

export interface EvidenceRef {
  refId: string
  detector: string
  claim: string
  sourceFile: string
  summary: string
  frameNumbers: number[]
  flow: string
  wiresharkFilter: string
}

export interface ReportFindings {
  primaryFinding: string
  supportingEvidence: string[]
  confidenceScore: number
  alternativeHypotheses: string[]
  mitreTechniques: string[]
  evidenceRefIds: string[]
  directEvidence: string[]
  uncertainties: string[]
  observation: string
  inference: string
  recommendation: string
}

export interface ReportImpact {
  affectedAssets: string[]
  attackType: string
  riskLevel: string
}

export interface ReportRecommendedActions {
  immediateContainment: string[]
  validationSteps: string[]
  longerTermHardening: string[]
}

export interface ReportGuardrails {
  dataValidityCheck: string
  toolOutputValidation: string
  humanReviewRequired: string
}

export interface ForensicReport {
  header: ReportHeader
  evidence: ReportEvidence
  findings: ReportFindings
  impact: ReportImpact
  recommendedActions: ReportRecommendedActions
  guardrailVerification: ReportGuardrails
  analystSummaryMarkdown: string
}

export interface GuardrailAudit {
  inputValidity: Record<string, unknown>
  toolValidation: Record<string, unknown>
  claimChecks: Array<Record<string, unknown>>
  contradictions: string[]
  confidenceDecision: Record<string, unknown>
  humanReviewRequired: string
  readOnlyMode: boolean
}

export interface RunMetrics {
  status: string
  runtimeSecondsTotal: number
  phaseTimingsSeconds: Record<string, number>
  cpuPercentPeak: number | null
  ramMbPeak: number | null
  provider: string
  model: string
  fallbackUsed: boolean
  llmTokensIn: number
  llmTokensOut: number
  artifactBytes: Record<string, number>
  costAssumptions: Record<string, number | string | boolean>
  costCompute: number
  costLlm: number
  costStorage: number
  estimatedCostTotal: number
}

export interface CreateAnalysisInput {
  file?: File
  pcapPath?: string
  provider?: string
  model?: string
  useAi?: boolean
  requireAi?: boolean
}
