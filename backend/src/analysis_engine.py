from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
import uuid

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, PcapReader

from analyzer import analyze_pcap_summary
from detectors import collect_all_findings
from deep_dive import build_deep_dive, render_deep_dive_markdown
from flow_analysis import build_attack_flow
from forensic_schema import (
    EvidenceBlock,
    EvidenceRef,
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
from report_ai import generate_report_result
from tool_executor import ToolExecutor, ToolPolicy

MITRE_BY_DETECTOR = {
    "external_rdp": ["T1133 - External Remote Services", "T1021.001 - Remote Desktop Protocol"],
    "external_port_scans": ["T1595 - Active Scanning"],
    "smb_rpc_scans": ["T1018 - Remote System Discovery", "T1021.002 - SMB/Windows Admin Shares"],
    "temp_sh_traffic": ["T1567 - Exfiltration Over Web Service"],
    "large_http_posts": ["T1567 - Exfiltration Over Web Service"],
    "outbound_exfiltration_candidates": ["T1041 - Exfiltration Over C2 Channel", "T1567 - Exfiltration Over Web Service"],
    "rdp_payload_deployment": ["T1021.001 - Remote Desktop Protocol"],
    "manual_payload_deployment": ["T1021.002 - SMB/Windows Admin Shares", "T1105 - Ingress Tool Transfer"],
}


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
    guardrail_audit: dict


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
            input_validity = self.guardrails.describe_input(req.pcap_path)
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
                report_findings["suspected_attack_flow"] = deep_dive.get("suspected_attack_flow")

            report_result = self.executor.execute(
                "reasoning",
                generate_report_result,
                summary,
                report_findings,
                provider=req.provider,
                model=req.model,
                use_ai=plan.use_llm_reasoning,
                require_ai=req.require_ai,
                policy=ToolPolicy(timeout_seconds=300, retries=1),
                fallback=lambda *args, **kwargs: generate_report_result(
                    summary,
                    report_findings,
                    provider=req.provider,
                    model=req.model,
                    use_ai=False,
                    require_ai=False,
                ),
            )

            markdown_report = report_result.text
            if deep_dive:
                markdown_report = f"{markdown_report}\n\n{render_deep_dive_markdown(deep_dive)}"

        with tracker.phase("report"):
            structured, guardrail_audit = self._build_forensic_report(
                req=req,
                metadata=metadata,
                summary=summary,
                findings=findings,
                markdown_report=markdown_report,
                deep_dive=deep_dive,
                zero_day=zero_day,
                input_validity=input_validity,
            )

        report_json_payload = structured.model_dump()
        guardrail_audit_payload = guardrail_audit
        artifact_bytes = {
            "report_json": len(json.dumps(report_json_payload, indent=2).encode("utf-8")),
            "report_markdown": len(markdown_report.encode("utf-8")),
            "guardrail_audit": len(json.dumps(guardrail_audit_payload, indent=2).encode("utf-8")),
        }
        compute_cost, llm_cost, storage_cost, total_cost, cost_assumptions = estimate_cost(
            tracker.total_runtime_seconds(),
            report_result.llm_tokens_in,
            report_result.llm_tokens_out,
            artifact_bytes_total=sum(artifact_bytes.values()),
        )

        metrics = RunMetrics(
            status="completed",
            runtime_seconds_total=round(tracker.total_runtime_seconds(), 3),
            phase_timings_seconds={k: round(v, 3) for k, v in tracker.phase_timings.items()},
            cpu_percent_peak=tracker.cpu_percent_peak,
            ram_mb_peak=round(tracker.ram_mb_peak, 3) if tracker.ram_mb_peak is not None else None,
            provider=report_result.provider,
            model=report_result.model,
            fallback_used=report_result.fallback_used,
            llm_tokens_in=report_result.llm_tokens_in,
            llm_tokens_out=report_result.llm_tokens_out,
            artifact_bytes=artifact_bytes,
            cost_assumptions=cost_assumptions,
            cost_compute=round(compute_cost, 6),
            cost_llm=round(llm_cost, 6),
            cost_storage=round(storage_cost, 6),
            estimated_cost_total=round(total_cost, 6),
        )

        return AnalysisArtifacts(
            report_json=report_json_payload,
            report_markdown=markdown_report,
            metrics=metrics.model_dump(),
            guardrail_audit=guardrail_audit_payload,
        )

    def _extract_metadata(self, pcap_path: str) -> dict[str, Any]:
        path = Path(pcap_path).resolve()
        size = path.stat().st_size
        packet_count = 0
        flow_set: set[tuple[Any, ...]] = set()
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

    def _zero_day_heuristics(self, summary: dict[str, Any], findings: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
        unusual_port_count = len(summary.get("unusual_ports", []))
        unusual_proto_count = len(summary.get("unusual_protocols", []))
        avg_packet_size = float(summary.get("average_packet_size", 0.0) or 0.0)
        packet_count = int(metadata.get("packet_count", 0))

        burst_flag = packet_count > 1_000_000
        entropy_proxy_flag = unusual_port_count > 15 or unusual_proto_count > 5
        handshake_fail_proxy = len(findings.get("external_rdp", {}).get("sessions", [])) > 50 and not findings.get("external_rdp", {}).get("patient_zero_candidate")
        external_scan_proxy = any(
            item.get("suspicious")
            for item in findings.get("external_port_scans", {}).get("sources", [])
        )

        anomaly_score = 0.0
        anomaly_score += 0.3 if burst_flag else 0.0
        anomaly_score += 0.4 if entropy_proxy_flag else 0.0
        anomaly_score += 0.3 if handshake_fail_proxy else 0.0
        anomaly_score += 0.2 if external_scan_proxy else 0.0

        return {
            "burst_anomaly": burst_flag,
            "entropy_outlier": entropy_proxy_flag,
            "failed_handshake_anomaly": handshake_fail_proxy,
            "average_packet_size": avg_packet_size,
            "anomaly_score": round(min(1.0, anomaly_score), 3),
        }

    def _build_forensic_report(
        self,
        *,
        req: AnalysisRequest,
        metadata: dict[str, Any],
        summary: dict[str, Any],
        findings: dict[str, Any],
        markdown_report: str,
        deep_dive: dict[str, Any] | None,
        zero_day: dict[str, Any],
        input_validity: dict[str, Any],
    ) -> tuple[ForensicReport, dict[str, Any]]:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"

        evidence_refs = self._build_evidence_refs(req.pcap_path, metadata, findings)
        ioc_list, suspicious_sessions, key_flows = self._collect_iocs_and_sessions(findings, evidence_refs)
        timeline = self._collect_timeline(findings, deep_dive, zero_day)
        direct_evidence = [ref.summary for ref in evidence_refs[:6]]

        confidence = self._confidence_score(findings, zero_day)
        attack_type, risk_level = self._impact_summary(findings, zero_day, confidence)
        mitre_techniques = self._collect_mitre_techniques(evidence_refs)

        observation = f"Observed {metadata.get('packet_count', 0)} packets across {metadata.get('flow_count', 0)} flows."
        inference = f"Likely attack class: {attack_type} with risk level {risk_level}."
        recommendation = self._recommendation_summary(findings, attack_type, confidence)

        observation, inference, recommendation = self.guardrails.enforce_output_sections(
            observation,
            inference,
            recommendation,
        )

        tool_validation = self.guardrails.validate_tool_outputs(summary, findings)
        tool_validation_detail = self.guardrails.describe_tool_validation(summary, findings)
        primary_finding = self._primary_finding(attack_type, findings)
        uncertainties = self._build_uncertainties(findings, zero_day, confidence, markdown_report)

        claim_checks, contradictions = self.guardrails.evaluate_consistency(
            attack_type=attack_type,
            primary_finding=primary_finding,
            inference=inference,
            markdown_report=markdown_report,
            evidence_refs=[ref.model_dump() for ref in evidence_refs],
            patient_zero_candidate=findings.get("external_rdp", {}).get("patient_zero_candidate"),
            has_lateral_evidence=self._has_lateral_evidence(findings),
        )
        guardrail = self.guardrails.apply_policy(confidence, tool_validation, contradictions)

        if guardrail.human_review_required == "Yes":
            primary_finding = "Evidence is inconclusive for autonomous high-confidence conclusion."
            inference = f"{inference} Human analyst review is required due to {guardrail.policy_reason}."
            if contradictions:
                uncertainties.append(
                    "Consistency checks found mismatches between structured claims and supporting evidence."
                )

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
                evidence_refs=evidence_refs,
            ),
            findings=FindingsBlock(
                primary_finding=primary_finding,
                supporting_evidence=[ref.summary for ref in evidence_refs[:8]],
                confidence_score=round(confidence, 3),
                alternative_hypotheses=[
                    "Benign but unusual traffic spike",
                    "Partial capture causing missing context",
                ],
                mitre_techniques=mitre_techniques,
                evidence_ref_ids=[ref.ref_id for ref in evidence_refs[:8]],
                direct_evidence=direct_evidence,
                uncertainties=sorted(set(uncertainties)),
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

        audit = self.guardrails.build_audit(
            input_validity=input_validity,
            tool_validation=tool_validation_detail,
            claim_checks=claim_checks,
            contradictions=contradictions,
            confidence_score=confidence,
            confidence_threshold=0.65,
            result=guardrail,
        )
        return report, audit.to_dict()

    def _primary_finding(self, attack_type: str, findings: dict[str, Any]) -> str:
        if attack_type == "exfiltration":
            return "Outbound transfer patterns indicate likely data exfiltration activity."
        if attack_type == "reconnaissance/scanning":
            return "External reconnaissance activity targeted internal hosts across multiple ports."
        if attack_type == "scan/lateral-movement":
            return "Internal scanning and lateral-movement indicators were observed across multiple hosts."
        if attack_type == "brute-force or remote-access compromise":
            patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate") or {}
            internal_ip = patient_zero.get("internal_ip", "an internal host")
            return f"External RDP access likely established initial access into {internal_ip}."
        if attack_type == "anomalous/unknown":
            return "Anomalous traffic exceeded baseline heuristics but does not map cleanly to a known intrusion pattern."
        return "No single attack path reached a high-confidence autonomous conclusion."

    def _confidence_score(self, findings: dict[str, Any], zero_day: dict[str, Any]) -> float:
        score = 0.1

        patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate") or {}
        if patient_zero:
            score += 0.12
            if patient_zero.get("handshake_complete"):
                score += 0.08
            if patient_zero.get("application_packets", 0) > 0:
                score += 0.08
            if patient_zero.get("post_login_unique_internal_targets", 0) >= 3:
                score += 0.1
            elif patient_zero.get("post_login_unique_internal_targets", 0) > 0:
                score += 0.04

        external_scans = [item for item in findings.get("external_port_scans", {}).get("sources", []) if item.get("suspicious")]
        if external_scans:
            strongest_recon = external_scans[0]
            score += 0.05
            if strongest_recon.get("severity") == "high":
                score += 0.05
            if strongest_recon.get("unique_ports", 0) >= 50:
                score += 0.03

        smb_scanners = [item for item in findings.get("smb_rpc_scans", {}).get("scanners", []) if item.get("suspicious")]
        if smb_scanners:
            strongest_scan = smb_scanners[0]
            score += 0.1
            if strongest_scan.get("unique_targets", 0) >= 20:
                score += 0.06
            elif strongest_scan.get("unique_targets", 0) >= 10:
                score += 0.04
            if strongest_scan.get("sample_events"):
                score += 0.02

        dcerpc_events = findings.get("dcerpc_account_activity", {}).get("events", [])
        if dcerpc_events:
            score += 0.04
            if any(item.get("possible_account_or_group_change") for item in dcerpc_events):
                score += 0.05

        exfil_flows = findings.get("outbound_exfiltration_candidates", {}).get("flows", [])
        if exfil_flows:
            strongest_exfil = exfil_flows[0]
            score += 0.08
            if strongest_exfil.get("severity") == "high":
                score += 0.14
            elif strongest_exfil.get("severity") == "medium":
                score += 0.1
            else:
                score += 0.05
            if strongest_exfil.get("temp_sh_mentions", 0) > 0:
                score += 0.05
            if strongest_exfil.get("sample_events"):
                score += 0.02

        manual_drop = findings.get("manual_payload_deployment", {}).get("candidates", [])
        if manual_drop:
            strongest_drop = manual_drop[0]
            score += 0.1
            if strongest_drop.get("manual_drop_score", 0) >= 80:
                score += 0.08
            if strongest_drop.get("targets_with_admin_share_markers", 0) > 0:
                score += 0.04
            if strongest_drop.get("targets_with_remote_exec_markers", 0) > 0:
                score += 0.05
        else:
            spreaders = [item for item in findings.get("rdp_payload_deployment", {}).get("spreaders", []) if item.get("suspicious")]
            if spreaders:
                score += 0.08
                if spreaders[0].get("unique_targets", 0) >= 5:
                    score += 0.04

        score += min(0.08, float(zero_day.get("anomaly_score", 0.0)) * 0.16)

        if patient_zero and not (
            smb_scanners
            or exfil_flows
            or manual_drop
            or [item for item in findings.get("rdp_payload_deployment", {}).get("spreaders", []) if item.get("suspicious")]
        ):
            score -= 0.08
        if external_scans and not (patient_zero or smb_scanners or exfil_flows or manual_drop):
            score = min(score, 0.58)
        if exfil_flows and not any(flow.get("sample_events") for flow in exfil_flows[:2]):
            score -= 0.03
        if zero_day.get("anomaly_score", 0.0) > 0 and not (
            patient_zero or external_scans or smb_scanners or dcerpc_events or exfil_flows or manual_drop
        ):
            score = min(score, 0.45)

        return max(0.0, min(1.0, round(score, 3)))

    def _impact_summary(self, findings: dict[str, Any], zero_day: dict[str, Any], confidence: float) -> tuple[str, str]:
        if findings.get("outbound_exfiltration_candidates", {}).get("flows"):
            attack = "exfiltration"
        elif findings.get("smb_rpc_scans", {}).get("scanners"):
            attack = "scan/lateral-movement"
        elif any(item.get("suspicious") for item in findings.get("external_port_scans", {}).get("sources", [])):
            attack = "reconnaissance/scanning"
        elif findings.get("external_rdp", {}).get("patient_zero_candidate"):
            attack = "brute-force or remote-access compromise"
        elif zero_day.get("anomaly_score", 0.0) >= 0.5:
            attack = "anomalous/unknown"
        else:
            attack = "unknown"

        if attack == "reconnaissance/scanning" and confidence >= 0.65:
            risk = "medium"
        elif confidence >= 0.8:
            risk = "high"
        elif confidence >= 0.6:
            risk = "medium"
        else:
            risk = "low"
        return attack, risk

    def _recommendation_summary(self, findings: dict[str, Any], attack_type: str, confidence: float) -> str:
        if confidence < 0.45:
            return "Preserve the PCAP and perform manual analyst review before making high-confidence containment decisions."
        if attack_type == "exfiltration":
            return "Prioritize containment of the suspected source host, review outbound destinations, and validate possible data-loss paths in packet and host telemetry."
        if attack_type == "scan/lateral-movement":
            return "Isolate the likely pivot host, validate SMB/RPC and internal RDP activity, and review downstream targets for lateral movement."
        if attack_type == "reconnaissance/scanning":
            return "Block or monitor the suspicious external source, validate the targeted internal hosts, and confirm whether reconnaissance progressed to authenticated access."
        if attack_type == "brute-force or remote-access compromise":
            return "Contain the suspected patient-zero host, review remote-access exposure and credentials, and verify follow-on lateral activity."
        return "Contain suspicious source hosts, verify affected assets, and perform follow-up validation."

    def _affected_assets(self, findings: dict[str, Any]) -> list[str]:
        assets = set()
        patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate")
        if patient_zero and patient_zero.get("internal_ip"):
            assets.add(patient_zero["internal_ip"])

        for spread in findings.get("rdp_payload_deployment", {}).get("spreaders", []):
            if spread.get("src_ip"):
                assets.add(spread["src_ip"])
        return sorted(assets)

    def _collect_iocs_and_sessions(
        self,
        findings: dict[str, Any],
        evidence_refs: list[EvidenceRef],
    ) -> tuple[list[str], list[str], list[str]]:
        iocs: list[str] = []
        sessions: list[str] = []
        key_flows = [ref.summary for ref in evidence_refs[:8]]

        patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate")
        if patient_zero:
            ext = patient_zero.get("external_ip")
            intl = patient_zero.get("internal_ip")
            if ext:
                iocs.append(f"ip:{ext}")
            if intl:
                iocs.append(f"ip:{intl}")

        for source in findings.get("external_port_scans", {}).get("sources", [])[:5]:
            src_ip = source.get("src_ip")
            if src_ip:
                iocs.append(f"ip:{src_ip}")
                sessions.append(
                    f"External scan src={src_ip} ports={source.get('unique_ports')} targets={source.get('unique_targets')}"
                )

        for scanner in findings.get("smb_rpc_scans", {}).get("scanners", [])[:5]:
            sessions.append(
                f"SMB/RPC scan src={scanner.get('src_ip')} targets={scanner.get('unique_targets')}"
            )

        for flow in findings.get("outbound_exfiltration_candidates", {}).get("flows", [])[:5]:
            sessions.append(
                f"Outbound flow {flow.get('src_ip')} -> {flow.get('dst_ip')}:{flow.get('dst_port')} bytes={flow.get('total_bytes')}"
            )

        return sorted(set(iocs)), sessions, key_flows

    def _collect_timeline(self, findings: dict[str, Any], deep_dive: dict[str, Any] | None, zero_day: dict[str, Any]) -> list[str]:
        events: list[str] = []

        if deep_dive:
            recon = deep_dive.get("reconnaissance", {})
            recon_ts = recon.get("first_seen")
            if recon_ts:
                events.append(f"{recon_ts} - reconnaissance indicators")
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
            "suspicious_external_port_scanners": findings.get("external_port_scans", {}).get("sources", []),
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

    def _collect_mitre_techniques(self, evidence_refs: list[EvidenceRef]) -> list[str]:
        techniques = set()
        for ref in evidence_refs:
            for technique in MITRE_BY_DETECTOR.get(ref.detector, []):
                techniques.add(technique)
        return sorted(techniques)

    def _build_uncertainties(
        self,
        findings: dict[str, Any],
        zero_day: dict[str, Any],
        confidence: float,
        markdown_report: str,
    ) -> list[str]:
        uncertainties = [
            "Results are derived from packet evidence only; host telemetry and endpoint logs were not available.",
            "Frame references are sampled from matching flows and should be manually validated in Wireshark for final reporting.",
        ]
        if confidence < 0.65:
            uncertainties.append("Overall confidence remained below the autonomous decision threshold.")
        if zero_day.get("anomaly_score", 0.0) > 0:
            uncertainties.append("Anomaly scoring is heuristic and may vary across different network baselines.")
        if not findings.get("manual_payload_deployment", {}).get("candidates"):
            uncertainties.append("Payload deployment remains inferred unless RDP plus admin-share or remote-exec markers are present.")
        if "heuristic" in markdown_report.lower():
            uncertainties.append("The generated report itself marks parts of the conclusion as heuristic or incomplete.")
        return uncertainties

    def _has_lateral_evidence(self, findings: dict[str, Any]) -> bool:
        return bool(
            findings.get("smb_rpc_scans", {}).get("scanners")
            or findings.get("rdp_payload_deployment", {}).get("spreaders")
            or findings.get("manual_payload_deployment", {}).get("candidates")
        )

    def _build_evidence_refs(self, pcap_path: str, metadata: dict[str, Any], findings: dict[str, Any]) -> list[EvidenceRef]:
        source_file = metadata.get("filename", Path(pcap_path).name)
        evidence_refs: list[EvidenceRef] = []

        patient_zero = findings.get("external_rdp", {}).get("patient_zero_candidate")
        if patient_zero:
            external_ip = patient_zero.get("external_ip")
            internal_ip = patient_zero.get("internal_ip")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id="EV-001",
                    detector="external_rdp",
                    claim="patient_zero",
                    source_file=source_file,
                    summary=f"External RDP session {external_ip} -> {internal_ip} reached the strongest patient-zero confidence.",
                    frame_numbers=self._frame_numbers_for_tcp_pair(pcap_path, external_ip, internal_ip, 3389),
                    flow=f"{external_ip} -> {internal_ip}:3389",
                    wireshark_filter=f"ip.addr == {external_ip} and ip.addr == {internal_ip} and tcp.port == 3389",
                )
            )

        for source in findings.get("external_port_scans", {}).get("sources", [])[:2]:
            src_ip = source.get("src_ip")
            sample_event = (source.get("sample_events") or [{}])[0]
            dst_ip = sample_event.get("dst_ip") or (source.get("top_targets") or [{}])[0].get("dst_ip")
            top_port = sample_event.get("dst_port")
            if top_port is None:
                top_port = (source.get("top_ports") or [{}])[0].get("port")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="external_port_scans",
                    claim="reconnaissance",
                    source_file=source_file,
                    summary=(
                        f"External source {src_ip} probed {source.get('unique_ports')} ports "
                        f"across {source.get('unique_targets')} internal targets."
                    ),
                    frame_numbers=self._frame_numbers_for_external_scan(pcap_path, src_ip, dst_ip, top_port),
                    flow=f"{src_ip} -> {dst_ip or 'internal targets'}:{top_port or 'multiple ports'}",
                    wireshark_filter=(
                        f"ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.flags.syn == 1 and tcp.flags.ack == 0"
                        if src_ip and dst_ip
                        else f"ip.src == {src_ip} and tcp.flags.syn == 1 and tcp.flags.ack == 0"
                    ),
                )
            )

        for scanner in findings.get("smb_rpc_scans", {}).get("scanners", [])[:2]:
            src_ip = scanner.get("src_ip")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="smb_rpc_scans",
                    claim="lateral_movement",
                    source_file=source_file,
                    summary=f"Internal host {src_ip} scanned {scanner.get('unique_targets')} SMB/RPC targets.",
                    frame_numbers=self._frame_numbers_for_scan_source(pcap_path, src_ip),
                    flow=f"{src_ip} -> internal hosts on 135/445",
                    wireshark_filter=f"ip.src == {src_ip} and (tcp.dstport == 135 or tcp.dstport == 445)",
                )
            )

        for hit in findings.get("temp_sh_traffic", {}).get("hits", [])[:2]:
            src_ip = hit.get("src_ip")
            dst_ip = hit.get("dst_ip")
            dst_port = hit.get("dst_port")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="temp_sh_traffic",
                    claim="exfiltration",
                    source_file=source_file,
                    summary=f"temp.sh indicator observed from {src_ip} to {dst_ip}:{dst_port}.",
                    frame_numbers=self._frame_numbers_for_temp_sh(pcap_path, src_ip, dst_ip, dst_port),
                    flow=f"{src_ip} -> {dst_ip}:{dst_port}",
                    wireshark_filter=f"(ip.src == {src_ip} and ip.dst == {dst_ip}) and frame contains \"temp.sh\"",
                )
            )

        for upload in findings.get("large_http_posts", {}).get("uploads", [])[:2]:
            src_ip = upload.get("src_ip")
            dst_ip = upload.get("dst_ip")
            dst_port = upload.get("dst_port")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="large_http_posts",
                    claim="exfiltration",
                    source_file=source_file,
                    summary=f"Large outbound HTTP upload from {src_ip} to {dst_ip}:{dst_port} inferred {upload.get('inferred_upload_bytes')} bytes.",
                    frame_numbers=self._frame_numbers_for_http_flow(pcap_path, src_ip, dst_ip, dst_port),
                    flow=f"{src_ip} -> {dst_ip}:{dst_port}",
                    wireshark_filter=f"ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.dstport == {dst_port} and http.request.method",
                )
            )

        for flow in findings.get("outbound_exfiltration_candidates", {}).get("flows", [])[:2]:
            src_ip = flow.get("src_ip")
            dst_ip = flow.get("dst_ip")
            dst_port = flow.get("dst_port")
            transport = str(flow.get("transport", "TCP"))
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="outbound_exfiltration_candidates",
                    claim="exfiltration",
                    source_file=source_file,
                    summary=f"Outbound exfiltration candidate {src_ip} -> {dst_ip}:{dst_port} transferred {flow.get('total_bytes')} bytes.",
                    frame_numbers=self._frame_numbers_for_flow(pcap_path, src_ip, dst_ip, dst_port, transport),
                    flow=f"{src_ip} -> {dst_ip}:{dst_port}",
                    wireshark_filter=f"ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.dstport == {dst_port}",
                )
            )

        for spread in findings.get("rdp_payload_deployment", {}).get("spreaders", [])[:1]:
            src_ip = spread.get("src_ip")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="rdp_payload_deployment",
                    claim="lateral_movement",
                    source_file=source_file,
                    summary=f"Internal RDP spread from {src_ip} touched {spread.get('unique_targets')} internal targets.",
                    frame_numbers=self._frame_numbers_for_internal_rdp_source(pcap_path, src_ip),
                    flow=f"{src_ip} -> internal hosts:3389",
                    wireshark_filter=f"ip.src == {src_ip} and tcp.dstport == 3389",
                )
            )

        for candidate in findings.get("manual_payload_deployment", {}).get("candidates", [])[:1]:
            src_ip = candidate.get("src_ip")
            top_target = (candidate.get("targets") or [{}])[0]
            dst_ip = top_target.get("dst_ip")
            evidence_refs.append(
                self._make_evidence_ref(
                    ref_id=f"EV-{len(evidence_refs) + 1:03d}",
                    detector="manual_payload_deployment",
                    claim="payload_deployment",
                    source_file=source_file,
                    summary=f"RDP plus SMB/DCERPC correlations suggest manual payload deployment from {src_ip} to {candidate.get('unique_targets')} hosts.",
                    frame_numbers=self._frame_numbers_for_manual_deployment(pcap_path, src_ip, dst_ip),
                    flow=f"{src_ip} -> {dst_ip or 'multiple internal hosts'}",
                    wireshark_filter=f"ip.src == {src_ip} and (tcp.dstport == 3389 or tcp.dstport == 445 or tcp.dstport == 135)",
                )
            )

        return evidence_refs

    def _make_evidence_ref(
        self,
        *,
        ref_id: str,
        detector: str,
        claim: str,
        source_file: str,
        summary: str,
        frame_numbers: list[int],
        flow: str,
        wireshark_filter: str,
    ) -> EvidenceRef:
        return EvidenceRef(
            ref_id=ref_id,
            detector=detector,
            claim=claim,
            source_file=source_file,
            summary=summary,
            frame_numbers=frame_numbers,
            flow=flow,
            wireshark_filter=wireshark_filter,
        )

    def _frame_numbers_for_flow(self, pcap_path: str, src_ip: str | None, dst_ip: str | None, port: int | None, transport: str, limit: int = 5) -> list[int]:
        if not src_ip or not dst_ip or port is None:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet:
                    continue
                if transport.upper() == "UDP":
                    if UDP not in packet:
                        continue
                    if packet[IP].src == src_ip and packet[IP].dst == dst_ip and int(packet[UDP].dport) == int(port):
                        results.append(frame_number)
                else:
                    if TCP not in packet:
                        continue
                    if packet[IP].src == src_ip and packet[IP].dst == dst_ip and int(packet[TCP].dport) == int(port):
                        results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_tcp_pair(self, pcap_path: str, ip_a: str | None, ip_b: str | None, port: int, limit: int = 5) -> list[int]:
        if not ip_a or not ip_b:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet or TCP not in packet:
                    continue
                src = packet[IP].src
                dst = packet[IP].dst
                if {src, dst} == {ip_a, ip_b} and (int(packet[TCP].sport) == port or int(packet[TCP].dport) == port):
                    results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_scan_source(self, pcap_path: str, src_ip: str | None, limit: int = 5) -> list[int]:
        if not src_ip:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet or TCP not in packet:
                    continue
                if packet[IP].src == src_ip and int(packet[TCP].dport) in {135, 445}:
                    results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_external_scan(
        self,
        pcap_path: str,
        src_ip: str | None,
        dst_ip: str | None,
        dst_port: int | None,
        limit: int = 5,
    ) -> list[int]:
        if not src_ip:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet or TCP not in packet:
                    continue
                if packet[IP].src != src_ip:
                    continue
                if dst_ip and packet[IP].dst != dst_ip:
                    continue
                if dst_port is not None and int(packet[TCP].dport) != int(dst_port):
                    continue
                flags = int(packet[TCP].flags)
                if not (flags & 0x02) or (flags & 0x10):
                    continue
                results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_temp_sh(self, pcap_path: str, src_ip: str | None, dst_ip: str | None, dst_port: int | None, limit: int = 5) -> list[int]:
        if not src_ip or not dst_ip:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet:
                    continue
                if packet[IP].src != src_ip or packet[IP].dst != dst_ip:
                    continue
                payload = bytes(packet[Raw].load).lower() if Raw in packet else b""
                dns_names: list[str] = []
                if DNS in packet and DNSQR in packet:
                    query = packet[DNS].qd
                    if query and getattr(query, "qname", None):
                        raw_name = query.qname
                        dns_names = [
                            raw_name.decode("utf-8", errors="ignore").lower()
                            if isinstance(raw_name, (bytes, bytearray))
                            else str(raw_name).lower()
                        ]
                if b"temp.sh" in payload or any("temp.sh" in name for name in dns_names):
                    results.append(frame_number)
                elif dst_port is not None and TCP in packet and int(packet[TCP].dport) == int(dst_port):
                    results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_http_flow(self, pcap_path: str, src_ip: str | None, dst_ip: str | None, dst_port: int | None, limit: int = 5) -> list[int]:
        if not src_ip or not dst_ip or dst_port is None:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet or TCP not in packet or Raw not in packet:
                    continue
                if packet[IP].src != src_ip or packet[IP].dst != dst_ip or int(packet[TCP].dport) != int(dst_port):
                    continue
                payload = bytes(packet[Raw].load)[:16]
                if payload.startswith((b"POST ", b"PUT ", b"PATCH ")):
                    results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_internal_rdp_source(self, pcap_path: str, src_ip: str | None, limit: int = 5) -> list[int]:
        if not src_ip:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet or TCP not in packet:
                    continue
                if packet[IP].src == src_ip and int(packet[TCP].dport) == 3389:
                    results.append(frame_number)
                if len(results) >= limit:
                    break
        return results

    def _frame_numbers_for_manual_deployment(self, pcap_path: str, src_ip: str | None, dst_ip: str | None, limit: int = 5) -> list[int]:
        if not src_ip:
            return []
        results: list[int] = []
        with PcapReader(str(Path(pcap_path).resolve())) as pcap:
            for frame_number, packet in enumerate(pcap, start=1):
                if IP not in packet or TCP not in packet:
                    continue
                if packet[IP].src != src_ip:
                    continue
                if dst_ip and packet[IP].dst != dst_ip:
                    continue
                if int(packet[TCP].dport) in {135, 445, 3389}:
                    results.append(frame_number)
                if len(results) >= limit:
                    break
        return results
