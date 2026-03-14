from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import uuid

from scapy.all import IP, TCP, UDP, PcapReader

from analyzer import analyze_pcap_summary
from detectors import collect_all_findings
from deep_dive import build_deep_dive, render_deep_dive_markdown
from flow_analysis import build_attack_flow
from forensic_schema import (
    EvidenceBlock,
    FindingsBlock,
    ForensicReport,
    GuardrailVerificationBlock,
    HeaderBlock,
    ImpactBlock,
    RecommendedActionsBlock,
    RunMetrics,
)
from guardrails import Guardrails
from observability import MetricsTracker, estimate_cost
from planner import AnalysisPlanner
from report_ai import generate_report
from tool_executor import ToolExecutor, ToolPolicy


@dataclass
class AnalysisRequest:
    pcap_path: str
    provider: str = "gemini"
    model: str | None = None
    use_ai: bool = True
    require_ai: bool = False


@dataclass
class AnalysisArtifacts:
    report_json: dict
    report_markdown: str
    metrics: dict


class AnalysisEngine:
    def __init__(self) -> None:
        self.guardrails = Guardrails()
        self.planner = AnalysisPlanner()
        self.executor = ToolExecutor(
            allowed_tools={
                "pcap_summary",
                "collect_findings",
                "deep_dive",
                "reasoning",
                "zero_day_heuristics",
            }
        )

    def run(self, req: AnalysisRequest) -> AnalysisArtifacts:
        tracker = MetricsTracker()

        with tracker.phase("ingest"):
            self.guardrails.validate_input(req.pcap_path)
            metadata = self._extract_metadata(req.pcap_path)
            plan = self.planner.create_plan(metadata, req.use_ai)

        with tracker.phase("parse"):
            summary = self.executor.execute(
                "pcap_summary",
                analyze_pcap_summary,
                req.pcap_path,
                policy=ToolPolicy(timeout_seconds=180, retries=1),
            )

        with tracker.phase("analysis"):
            findings = self.executor.execute(
                "collect_findings",
                collect_all_findings,
                req.pcap_path,
                policy=ToolPolicy(timeout_seconds=300, retries=1),
            )
            deep_dive = None
            if plan.run_deep_dive:
                deep_dive = self.executor.execute(
                    "deep_dive",
                    build_deep_dive,
                    req.pcap_path,
                    findings,
                    policy=ToolPolicy(timeout_seconds=300, retries=0),
                )

            zero_day = {}
            if plan.enable_zero_day_heuristics:
                zero_day = self.executor.execute(
                    "zero_day_heuristics",
                    self._zero_day_heuristics,
                    summary,
                    findings,
                    metadata,
                )

        with tracker.phase("reason"):
            report_findings = {**findings, "zero_day_heuristics": zero_day}
            if deep_dive:
                report_findings["deep_dive"] = deep_dive

            markdown_report = self.executor.execute(
                "reasoning",
                generate_report,
                summary,
                report_findings,
                provider=req.provider,
                model=req.model,
                use_ai=plan.use_llm_reasoning,
                require_ai=req.require_ai,
                policy=ToolPolicy(timeout_seconds=300, retries=1),
                fallback=lambda *args, **kwargs: generate_report(summary, report_findings, use_ai=False),
            )

            if deep_dive:
                markdown_report = f"{markdown_report}\n\n{render_deep_dive_markdown(deep_dive)}"

        with tracker.phase("report"):
            structured = self._build_forensic_report(
                req=req,
                metadata=metadata,
                summary=summary,
                findings=findings,
                markdown_report=markdown_report,
                deep_dive=deep_dive,
                zero_day=zero_day,
            )

        llm_tokens_in = 0
        llm_tokens_out = 0
        compute_cost, llm_cost, storage_cost, total_cost = estimate_cost(llm_tokens_in, llm_tokens_out)

        metrics = RunMetrics(
            status="completed",
            runtime_seconds_total=round(tracker.total_runtime_seconds(), 3),
            phase_timings_seconds={k: round(v, 3) for k, v in tracker.phase_timings.items()},
            cpu_percent_peak=tracker.cpu_percent_peak,
            ram_mb_peak=round(tracker.ram_mb_peak, 3) if tracker.ram_mb_peak is not None else None,
            llm_tokens_in=llm_tokens_in,
            llm_tokens_out=llm_tokens_out,
            cost_compute=round(compute_cost, 6),
            cost_llm=round(llm_cost, 6),
            cost_storage=round(storage_cost, 6),
            estimated_cost_total=round(total_cost, 6),
        )

        return AnalysisArtifacts(
            report_json=structured.model_dump(),
            report_markdown=markdown_report,
            metrics=metrics.model_dump(),
        )

    def _extract_metadata(self, pcap_path: str) -> dict:
        path = Path(pcap_path).resolve()
        size = path.stat().st_size
        packet_count = 0
        flow_set: set[tuple] = set()
        start_time = None
        end_time = None

        with PcapReader(str(path)) as pcap:
            for pkt in pcap:
                packet_count += 1
                ts = float(getattr(pkt, "time", 0.0))
                if start_time is None or ts < start_time:
                    start_time = ts
                if end_time is None or ts > end_time:
                    end_time = ts

                if IP in pkt:
                    proto = int(pkt[IP].proto)
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    sport = 0
                    dport = 0
                    if TCP in pkt:
                        sport = int(pkt[TCP].sport)
                        dport = int(pkt[TCP].dport)
                    elif UDP in pkt:
                        sport = int(pkt[UDP].sport)
                        dport = int(pkt[UDP].dport)
                    flow_set.add((src, dst, proto, sport, dport))

        return {
            "filename": path.name,
            "path": str(path),
            "size_bytes": size,
            "packet_count": packet_count,
            "flow_count": len(flow_set),
            "capture_start": datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat() if start_time else None,
            "capture_end": datetime.fromtimestamp(end_time, tz=timezone.utc).isoformat() if end_time else None,
        }

    def _zero_day_heuristics(self, summary: dict, findings: dict, metadata: dict) -> dict:
        unusual_port_count = len(summary.get("unusual_ports", []))
        unusual_proto_count = len(summary.get("unusual_protocols", []))
        avg_packet_size = float(summary.get("average_packet_size", 0.0) or 0.0)
        packet_count = int(metadata.get("packet_count", 0))

        burst_flag = packet_count > 1_000_000
        entropy_proxy_flag = unusual_port_count > 15 or unusual_proto_count > 5
        handshake_fail_proxy = len(findings.get("external_rdp", {}).get("sessions", [])) > 50 and not findings.get("external_rdp", {}).get("patient_zero_candidate")

        anomaly_score = 0
        anomaly_score += 0.3 if burst_flag else 0.0
        anomaly_score += 0.4 if entropy_proxy_flag else 0.0
        anomaly_score += 0.3 if handshake_fail_proxy else 0.0

        return {
            "burst_anomaly": burst_flag,
            "entropy_outlier": entropy_proxy_flag,
            "failed_handshake_anomaly": handshake_fail_proxy,
            "average_packet_size": avg_packet_size,
            "anomaly_score": round(min(1.0, anomaly_score), 3),
        }

    def _build_forensic_report(
        self,
        req: AnalysisRequest,
        metadata: dict,
        summary: dict,
        findings: dict,
        markdown_report: str,
        deep_dive: dict | None,
        zero_day: dict,
    ) -> ForensicReport:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

        ioc_list, suspicious_sessions, key_flows = self._collect_iocs_and_sessions(findings)
        timeline = self._collect_timeline(findings, deep_dive, zero_day)

        confidence = self._confidence_score(findings, zero_day)
        attack_type, risk_level = self._impact_summary(findings, zero_day, confidence)

        observation = f"Observed {metadata.get('packet_count', 0)} packets across {metadata.get('flow_count', 0)} flows."
        inference = f"Likely attack class: {attack_type} with risk level {risk_level}."
        recommendation = "Contain suspicious source hosts, verify affected assets, and perform follow-up validation."

        observation, inference, recommendation = self.guardrails.enforce_output_sections(
            observation,
            inference,
            recommendation,
        )

        tool_validation = self.guardrails.validate_tool_outputs(summary, findings)
        guardrail = self.guardrails.apply_policy(confidence, tool_validation)

        primary_finding = (
            f"High-confidence {attack_type} activity detected."
            if guardrail.human_review_required == "No"
            else "Evidence is inconclusive for autonomous high-confidence conclusion."
        )

        if guardrail.human_review_required == "Yes":
            inference = f"{inference} Human analyst review is required due to {guardrail.policy_reason}."

        report = ForensicReport(
            header=HeaderBlock(
                case_id=case_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                data_sources=[metadata.get("path", req.pcap_path)],
            ),
            evidence=EvidenceBlock(
                key_packets_flows=key_flows,
                ioc_list=ioc_list,
                suspicious_sessions=suspicious_sessions,
                correlated_events_timeline=timeline,
            ),
            findings=FindingsBlock(
                primary_finding=primary_finding,
                supporting_evidence=key_flows[:8],
                confidence_score=round(confidence, 3),
                alternative_hypotheses=[
                    "Benign but unusual traffic spike",
                    "Partial capture causing missing context",
                ],
                observation=observation,
                inference=inference,
                recommendation=recommendation,
            ),
            impact=ImpactBlock(
                affected_assets=self._affected_assets(findings),
                attack_type=attack_type,
                risk_level=risk_level,
            ),
            recommended_actions=RecommendedActionsBlock(
                immediate_containment=[
                    "Isolate top suspicious internal host(s)",
                    "Block high-risk external IPs tied to suspicious sessions",
                ],
                validation_steps=[
                    "Validate suspicious sessions in Wireshark using generated filters",
                    "Cross-check findings with host/event telemetry if available",
                ],
                longer_term_hardening=[
                    "Enforce network segmentation for critical assets",
                    "Harden remote administration access and monitor lateral movement",
                ],
            ),
            guardrail_verification=GuardrailVerificationBlock(
                data_validity_check=guardrail.data_validity_check,
                tool_output_validation=guardrail.tool_output_validation,
                human_review_required=guardrail.human_review_required,
            ),
            analyst_summary_markdown=markdown_report,
        )
        return report

    def _confidence_score(self, findings: dict, zero_day: dict) -> float:
        score = 0.2
        if findings.get("external_rdp", {}).get("patient_zero_candidate"):
            score += 0.25
        if findings.get("smb_rpc_scans", {}).get("scanners"):
            score += 0.15
        if findings.get("outbound_exfiltration_candidates", {}).get("flows"):
            score += 0.2
        if findings.get("manual_payload_deployment", {}).get("candidates"):
            score += 0.15
        score += min(0.1, float(zero_day.get("anomaly_score", 0.0)) * 0.2)
        return max(0.0, min(1.0, score))

    def _impact_summary(self, findings: dict, zero_day: dict, confidence: float) -> tuple[str, str]:
        if findings.get("outbound_exfiltration_candidates", {}).get("flows"):
            attack = "exfiltration"
        elif findings.get("smb_rpc_scans", {}).get("scanners"):
            attack = "scan/lateral-movement"
        elif findings.get("external_rdp", {}).get("patient_zero_candidate"):
            attack = "brute-force or remote-access compromise"
        elif zero_day.get("anomaly_score", 0.0) >= 0.5:
            attack = "anomalous/unknown"
        else:
            attack = "unknown"

        if confidence >= 0.8:
            risk = "high"
        elif confidence >= 0.6:
            risk = "medium"
        else:
            risk = "low"
        return attack, risk

    def _affected_assets(self, findings: dict) -> list[str]:
        assets = set()
        patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate")
        if patient_zero and patient_zero.get("internal_ip"):
            assets.add(patient_zero["internal_ip"])

        for spread in findings.get("rdp_payload_deployment", {}).get("spreaders", []):
            if spread.get("src_ip"):
                assets.add(spread["src_ip"])
        return sorted(assets)

    def _collect_iocs_and_sessions(self, findings: dict) -> tuple[list[str], list[str], list[str]]:
        iocs: list[str] = []
        sessions: list[str] = []
        key_flows: list[str] = []

        patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate")
        if patient_zero:
            ext = patient_zero.get("external_ip")
            intl = patient_zero.get("internal_ip")
            if ext:
                iocs.append(f"ip:{ext}")
            if intl:
                iocs.append(f"ip:{intl}")
            key_flows.append(f"External RDP session {ext} -> {intl}")

        for scanner in findings.get("smb_rpc_scans", {}).get("scanners", [])[:5]:
            sessions.append(
                f"SMB/RPC scan src={scanner.get('src_ip')} targets={scanner.get('unique_targets')}"
            )
            key_flows.append(
                f"Scanner {scanner.get('src_ip')} touched {scanner.get('unique_targets')} hosts"
            )

        for flow in findings.get("outbound_exfiltration_candidates", {}).get("flows", [])[:5]:
            sessions.append(
                f"Outbound flow {flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} bytes={flow.get('total_bytes')}"
            )
            key_flows.append(
                f"Exfil candidate {flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}"
            )

        return sorted(set(iocs)), sessions, key_flows

    def _collect_timeline(self, findings: dict, deep_dive: dict | None, zero_day: dict) -> list[str]:
        events: list[str] = []

        if deep_dive:
            init_access = deep_dive.get("initial_access", {})
            first_seen = init_access.get("first_seen")
            if first_seen:
                events.append(f"{first_seen} - potential initial access")
            lateral = deep_dive.get("lateral_movement_and_discovery", {})
            first_scan = lateral.get("first_scan_seen")
            if first_scan:
                events.append(f"{first_scan} - lateral/discovery signals")
            exfil = deep_dive.get("exfiltration", {})
            exfil_ts = exfil.get("first_exfil_indicator_seen")
            if exfil_ts:
                events.append(f"{exfil_ts} - exfiltration indicator")

        record = {
            "file": "runtime-case",
            "patient_zero_candidate": findings.get("external_rdp", {}).get("patient_zero_candidate"),
            "suspicious_smb_rpc_scanners": findings.get("smb_rpc_scans", {}).get("scanners", []),
            "possible_dcerpc_account_changes": findings.get("dcerpc_account_activity", {}).get("events", []),
            "possible_outbound_exfil_flows": findings.get("outbound_exfiltration_candidates", {}).get("flows", []),
            "large_http_uploads": findings.get("large_http_posts", {}).get("uploads", []),
            "suspicious_internal_rdp_spread": findings.get("rdp_payload_deployment", {}).get("spreaders", []),
            "manual_payload_deployment_candidates": findings.get("manual_payload_deployment", {}).get("candidates", []),
            "deep_dive": deep_dive,
            "deep_dive_focus_host": (deep_dive or {}).get("focus_host"),
        }
        flow = build_attack_flow([record])
        events.extend([f"{item.get('timestamp')} - {item.get('detail')}" for item in flow.get("timeline", [])[:10]])

        if zero_day.get("anomaly_score", 0.0) > 0:
            events.append(
                f"heuristic - anomaly_score={zero_day.get('anomaly_score')} burst={zero_day.get('burst_anomaly')} entropy={zero_day.get('entropy_outlier')}"
            )

        return [event for event in events if event]
