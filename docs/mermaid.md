flowchart TD
    U["User / Analyst"] --> FE["Next.js frontend"]

    subgraph FE_APP["Frontend"]
        F1["/analysis/new<br/>batch upload + profile selection"]
        F2["/total-jobs<br/>list, rerun, all-jobs summary"]
        F3["/total-jobs/{id}<br/>progress, dedupe, artifacts"]
        F4["Legacy child-job pages<br/>/analysis/{jobId}"]
    end

    FE --> F1
    FE --> F2
    FE --> F3
    FE --> F4

    F1 --> API_BATCH["POST /api/v1/analysis/batch"]
    F4 --> API_SINGLE["POST /api/v1/analysis"]
    F2 --> API_LIST["GET /api/v1/total-jobs<br/>GET /api/v1/total-jobs/summary/status"]
    F2 --> API_ALL["POST /api/v1/total-jobs/summary/enrich"]
    F3 --> API_ONE["GET /api/v1/total-jobs/{id}<br/>POST /api/v1/total-jobs/{id}/enrich"]

    subgraph STAGE1["Stage 1: child analysis"]
        S1["Create total_job + child analysis_job records"]
        S2["ProcessPoolExecutor<br/>batch-first fan-out"]
        S0["Batch child request policy<br/>use_ai=false<br/>enable_sandbox=false"]
        S3["AnalysisEngine.run"]
        S4["AnalysisPlanner<br/>profiles: fast | standard | full"]
        S5["Metadata + base findings"]
        S6["Deep dive<br/>fast: off<br/>standard: evidence-gated<br/>full: legacy threshold gate"]
        S7["Deterministic payload carving<br/>fast: off<br/>standard: deferred<br/>full: on"]
        S8["report.json / report.md<br/>metrics.json / guardrail_audit.json<br/>analysis_record.json"]
    end

    API_BATCH --> S1
    S1 --> S2
    S2 --> S0
    S0 --> S3
    API_SINGLE --> S3
    S3 --> S4
    S4 --> S5
    S5 --> S6
    S5 --> S7
    S6 --> S8
    S7 --> S8

    subgraph STORES["Persistence"]
        P1["outputs/analysis_jobs/<analysis_job_id>/"]
        P2["outputs/total_jobs/<total_job_id>/"]
        P3["outputs/total_jobs/__all_jobs_summary/"]
    end

    S8 --> P1
    S1 --> P2

    subgraph ENRICH["Stage 2: parent campaign enrichment"]
        E1["Load completed child analysis_record.json"]
        E2["Dedupe records before enrichment"]
        E3["Initial campaign summary<br/>report provider default: Gemini"]
        E4["Campaign weak-section planner<br/>planner provider default: OpenRouter"]
        E5["Sandbox verification for every deduped record"]
        E6["AI-authored tshark follow-up<br/>selected related files only"]
        E7["Delayed stage-2 payload carving<br/>persist under parent artifacts"]
        E8["Final campaign report<br/>same requested report provider"]
        E9["Write aggregate_summary, scan_results,<br/>initial_summary.md, campaign_plan.json,<br/>summary.json/.md, sandbox.json"]
    end

    API_ONE --> E1
    P1 --> E1
    E1 --> E2
    E2 --> E3
    E3 --> E4
    E2 --> E5
    E4 --> E6
    E5 --> E7
    E6 --> E8
    E7 --> E8
    E8 --> E9
    E9 --> P2

    subgraph ALLJOBS["Combined all-total-jobs summary"]
        A1["Collect completed child records<br/>across all total jobs"]
        A2["Reuse the same campaign route"]
        A3["Write mirrored artifacts + status.json"]
    end

    API_ALL --> A1
    P1 --> A1
    A1 --> A2
    A2 --> A3
    A3 --> P3
