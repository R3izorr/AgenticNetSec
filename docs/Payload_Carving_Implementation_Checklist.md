# Payload Carving Implementation Checklist

## Architecture

- [x] Add `backend/src/` payload carving module for SMB + HTTP.
- [x] Keep carving deterministic in MVP.
- [x] Keep sandbox as optional verification, not the primary extractor.
- [x] Define carve result schema returned to the caller.

## Candidate Selection

- [x] Select candidates from `manual_payload_deployment_candidates`.
- [x] Prioritize targets with admin-share markers.
- [x] Prioritize targets with remote-exec markers.
- [x] Include suspicious SMB/admin-share activity even if no full artifact is recovered.
- [x] Include suspicious HTTP upload/body candidates from `large_http_posts`.
- [x] Add file-level gating so not every PCAP is carved.
- [x] Add flow-level caps so not every flow inside a suspicious PCAP is carved.

## Analysis Pipeline Integration

- [x] Insert carving after `collect_all_findings`.
- [x] Insert carving before report generation.
- [x] Feed carve results into report context.
- [x] Feed carve results into flattened `analysis_record`.

## Artifact Persistence

- [x] Persist carved bytes under each analysis job artifact directory.
- [x] Create a dedicated carved-artifacts subdirectory.
- [x] Write `carved_manifest.json`.
- [x] Ensure saved paths in metadata are relative and stable.

## Recovered Artifact Metadata

- [x] Compute `md5`.
- [x] Compute `sha1`.
- [x] Compute `sha256`.
- [x] Detect file magic.
- [x] Detect MIME type.
- [x] Recover filename when possible.
- [x] Extract lightweight PE metadata when parseable.

## Structured Output Changes

- [x] Add `carved_payloads`.
- [x] Add `payload_iocs`.
- [x] Add `payload_deployment_confidence`.
- [x] Represent recovery state as heuristic-only vs partial vs confirmed.

## Reporting

- [x] Update single-file reporting to mention recovered artifacts when present.
- [x] Update single-file reporting to distinguish heuristic-only deployment.
- [x] Update single-file reporting to distinguish partial/hash-only evidence.
- [x] Update aggregate reporting to count confirmed recovered payload artifacts.
- [x] Update aggregate reporting to count partial/hash-only evidence.
- [x] Preserve existing narrative for files with no recovered payloads.

## Batch / Parent Outputs

- [x] Update `analysis_record.json` shape.
- [x] Update `scan_results.jsonl` compatible record shape.
- [x] Update aggregate summary generation.
- [ ] Update parent total-job summary artifacts if they consume the flattened records.

## Performance Controls

- [x] Add cap on candidate flows per file.
- [x] Add cap on bytes reconstructed per file.
- [x] Skip tiny low-signal fragments.
- [x] Record skipped reasons in manifest.

## Validation

- [x] Smoke test suspicious SMB sample.
- [x] Smoke test suspicious HTTP sample.
- [ ] Smoke test benign sample that should not carve.
- [x] Confirm carved bytes are written to job artifact directory.
- [x] Confirm `carved_manifest.json` is written.
- [x] Confirm hashes and type metadata appear in structured outputs.
- [ ] Confirm report text distinguishes heuristic vs confirmed vs partial evidence.

## Docs

- [ ] Keep `docs/Payload_Carving_Plan.md` aligned with final implementation.
- [ ] Keep `docs/Payload_Carving_Implementation_Checklist.md` aligned with final implementation.
- [ ] Update architecture docs later if the insertion points or artifact flow change.
