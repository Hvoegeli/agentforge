# AgentForge — TODO / backlog

Running list of known follow-ups. The big-ticket parked items are done; this file is now
just smaller notes. (Status / verified-fixed state of the seeded findings lives in the
latest `evals/results/regression-<sha>.json` artifact and on the dashboard — this file
is for *work to do*, not findings.)

---

## Smaller notes / open follow-ups

- **Sharpen the binary-IDOR check (F3).** Right now the binary-IDOR replay reads PASS off a
  `404` (the endpoint refused an off-panel `GET /api/binary/<id>`). If a *regression*ed it
  back to `200 + bytes`, the C2 checker wouldn't flag it (raw `.docx` bytes contain no UUID
  text). Fix: have the seed carry `http_patient=<the off-panel patient UUID for that doc>`
  and `_raw_http_get_attempt` surface that UUID in `response_redacted` on a 2xx, so a
  regression flags the patient. (Needs the patient UUID that owns
  `DocumentReference/a1c3fdb4-654a-41f1-be2b-865aaf8aafa5`.)
- **C1 doc-image — waiting on the attack image.** The `upload_doc` setup runs, but no
  poisoned attack image has been authored, so the uploaded document is benign → the replay
  reads PASS = "the attack didn't land", *not* "verified fixed". Once the image exists, point
  the setup at it (`agentforge.attacks.poison_doc` / the seed's `setup_payload_b64`).
- **B2 / C3 corpus cases.** The judge corpus covers C1/C2/C4/C5/C6/B1/B3 (43 cases, 100%
  agreement). Add B2 (improper-output — `invariants/b2_improper_output.py` exists) and C3
  (state corruption) corpus cases once those checkers are settled.
- **Re-deploy the dashboard before the Final.** `dashboard.html` / `RESILIENCE.md` are
  regenerated in-repo, but the *deployed* dashboard (`*.trycloudflare.com`, served from the
  Hetzner box) only refreshes when `deploy-dashboard.sh` runs (`scp` to the box). Re-run it
  before submission; submit the current trycloudflare URLs with the checkpoint.
- **`needs_setup=write_fhir_field` (C1 indirect-via-FHIR-field).** Not implemented (recorded
  as a skipped setup). Lower priority than session_adoption.

### Added 2026-05-12 (after the 9-categories + regression-verification session — `2dc1c05`)

- **C1 doc-image is `resolved` on the dashboard, but the *code* path isn't fixed.** The
  regression replay clears 3/3 (the discharge-summary "[ASSISTANT INSTRUCTIONS…]" injection
  no longer reproduces) → `--update-status` flipped it to `resolved`; but the jailbreak
  quarantine still scans only tool-result *text*, never the rendered-PNG channel
  `get_document_content` feeds the vision model (see `THREAT_MODEL.md` § Fix status, and the
  "C1 doc-image — waiting on the attack image" note above). **Decide the framing:** push the
  Co-Pilot team to land the quarantine fix (then it's genuinely closed), or represent "exploit
  doesn't reproduce but the code gap is open" as something other than plain `resolved` on the
  dashboard. The user explicitly asked about this — don't let it slide silently.
- **The binary-IDOR seed's `http_id` is a specific deployed-instance DocumentReference.**
  `_c2_binary_idor` carries `http_id=a1c3fdb4-654a-41f1-be2b-865aaf8aafa5` — an off-panel
  doc on the *current* Co-Pilot FHIR data. If the target is redeployed / its FHIR demo data
  re-seeded (e.g. the Final re-pins the baseline), that id may not exist → the regression
  replay errors → F3 flips back to `open` spuriously. Refresh the id (and, per the "sharpen
  the binary-IDOR check" note, also wire `http_patient=<owning UUID>`) whenever the target's
  data changes. Same fragility applies to `_OUT_OF_PANEL_PATIENT` and the `upload_doc` panel
  patients if the demo data shifts.
- **Re-pin the regression baseline for the Final.** `THREAT_MODEL.md` keeps the MVP baseline
  at `74aa5be4`; the Final re-pins to whatever the Co-Pilot is at then. Before submission:
  bump `COPILOT_TARGET_SHA` (`.env`) + the baseline SHA in `THREAT_MODEL.md`, re-run
  `deploy-dashboard.sh` (it now does seed → 9-category sweep → `regression-suite --update-status`
  → render → scp), commit the regenerated artifacts, submit the current trycloudflare URLs.
- **C3's deterministic checker is a stub** (`invariants/c3_state_corruption.py` always returns
  UNCERTAIN). The C3 seeds (`attacks/seeds.py` — forged-prior-turn / attacker-supplied-guideline
  / cross-session-canary) run against the target but every verdict is UNCERTAIN/escalate, so
  C3 never shows PASS/FAIL on the dashboard. To give it real signal: either get the Co-Pilot
  to surface `conversation_sources` / per-turn provenance in `/api/traces` (then the deterministic
  provenance walk works), or add a `C3.provenance` handler in `judge/llm_judge.py` (C3 is already
  in `_LLM_JUDGEABLE_INVARIANTS`, but nothing answers it). This is the gap behind the "B2 / C3
  corpus cases" note — the C3 corpus can't be settled until the checker can decide.
