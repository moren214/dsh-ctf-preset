# CTF Core Runtime Rules

## 1. Ground Truth & Evidence Chain
- Every claim (address, offset, key, vulnerability, flag) MUST be backed by a tool result `result_id` or exact workspace file/line evidence.
- Chain derived artifacts cleanly via `result_id` / `source_result_id` instead of re-encoding large blobs through chat turns.
- All tools classify failures using structured `error.kind` (`unsupported`, `missing`, `permission`, `conflict`, `timeout`, `network`, `dependency`, `encoding`, `size`), `error.retryable`, and `error.side_effect_may_have_occurred`. Wait and branch deterministically on `error.kind`.

## 2. Shared Workspace State (`ctf_graph`, `ctf_status`, `ctf_progress`)
- On start or handoff: check `ctf_graph(action: "board", summary_only: true)` and `ctf_status(action: "show")`.
- Record verified breakthroughs (`add_fact`) with `dedupe_key` and follow-up branches (`add_intent` / `start_race`).
- Claim intents atomically (`claim_intent`), preserve `lease_id`, and finalize (`finish_intent`, `done` or `dead`).
- In multi-branch Best-of-N races, call `cancel_race_siblings` as soon as a winning branch finishes.

## 3. Target Authorization & Submission
- Never target loopback or host metadata endpoints; obtain challenge endpoints via `ctf_arena(detail/container)` or `ctf_instance(create)` so network leases are recorded in `.ctf/runtime.db`.
- Before calling `submit_flag`, pre-check via `check_flag` (`dynamic: true` requires a recent recorded instance). Do not retry failed flags blindly; pass `retry_unknown: true` only when platform verdict was `unknown`.

## 4. Sandbox Tiers
- Use host zero-dependency tools (`inspect_attachment`, `inspect_elf`, `rev_query`, `calculate_offline`) before launching Docker.
- Docker sandbox is isolated (`--read-only`, `--cap-drop=ALL`, UID 10001). Unauthorized `bridge` egress is blocked by default; obtain platform target authorization first.
