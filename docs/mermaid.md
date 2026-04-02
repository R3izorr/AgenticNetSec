flowchart TD
    U["User / Analyst"] --> F["Frontend Next.js"]

    subgraph FE["Frontend"]
        F1["/analysis/new<br/>Batch-first upload form"]
        F2["analysis API client<br/>frontend/lib/api/analysis.ts"]
        F3["total-job hooks<br/>use-total-jobs / use-total-job-status"]
        F4["Future total-job page<br/>/total-jobs/[totalJobId]"]
    end

    F --> F1
    F1 --> F2
    F4 --> F3
    F2 --> API["FastAPI<br/>backend/api/app.py"]

    subgraph BE["Backend API Layer"]
        A1["POST /api/v1/analysis<br/>single-file path"]
        A2["POST /api/v1/analysis/batch<br/>batch-first path"]
        A3["GET /api/v1/total-jobs"]
        A4["GET /api/v1/total-jobs/{id}"]
        A5["POST /api/v1/total-jobs/{id}/enrich"]
        A6["GET child-job artifacts<br/>report / metrics / guardrail"]
        A7["GET total-job artifacts<br/>summary.json / summary.md / sandbox"]
    end

    API --> A1
    API --> A2
    API --> A3
    API --> A4
    API --> A5
    API --> A6
    API --> A7

    subgraph STORE["Persistence"]
        S1["JobStore<br/>outputs/analysis_jobs/<analysis_job_id>/"]
        S2["TotalJobStore<br/>outputs/total_jobs/<total_job_id>/"]
        S3["job.json"]
        S4["report.json / report.md<br/>metrics.json / guardrail_audit.json<br/>analysis_record.json"]
        S5["total_job.json"]
        S6["summary.json / summary.md / sandbox.json"]
    end

    A1 --> S1
    A2 --> S1
    A2 --> S2
    S1 --> S3
    S1 --> S4
    S2 --> S5
    S2 --> S6

    subgraph BATCH["Deterministic Batch Run"]
        B1["Create parent total_job"]
        B2["Create child analysis jobs"]
        B3["ProcessPoolExecutor<br/>min 2 workers"]
        B4["Child request flags<br/>use_ai=false<br/>enable_sandbox=false"]
        B5["AnalysisEngine.run(...)"]
    end

    A2 --> B1
    B1 --> B2
    B2 --> B3
    B3 --> B4
    B4 --> B5
    B2 --> S2
    B2 --> S1

    subgraph ENGINE["Analysis Core"]
        E1["planner.py"]
        E2["analyzer.py"]
        E3["detectors.py"]
        E4["deep_dive.py"]
        E5["report_ai.py<br/>deterministic fallback or provider-backed output"]
        E6["guardrails.py"]
        E7["analysis_record builder"]
    end

    B5 --> E1
    E1 --> E2
    E2 --> E3
    E3 --> E4
    E3 --> E6
    E4 --> E5
    E6 --> E5
    E5 --> E7
    E7 --> S4

    subgraph ENRICH["Delayed Parent Enrichment"]
        R1["Load child analysis_record.json"]
        R2["build_aggregate.py"]
        R3["generate_results_report.py"]
        R4["enrich_record.py<br/>sandbox-oriented enrichment"]
        R5["Write parent artifacts"]
    end

    A5 --> R1
    S4 --> R1
    R1 --> R2
    R1 --> R4
    R2 --> R3
    R3 --> R5
    R4 --> R5
    R5 --> S6

    A3 --> F3
    A4 --> F3
    A7 --> F4
