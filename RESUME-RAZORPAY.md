# Resume for Razorpay — Intern, Security Engineering

Base: `Melvin_Kannan_AI_Engineer_Resume.pdf`. Target: one page.

`<X>` = a number you must actually measure before you write it. Do not ship a
placeholder. If Pramaan does not produce the number, delete the clause — the
whole pitch of this project is that you report what you measured.

---

## Header

```
MELVIN KANNAN
AI Engineer · Security Automation
melvin.kannan@proton.me | +91 8590667321 | linkedin.com/in/melvin-kannan-800196283
github.com/Melvin0070 | Coimbatore, Tamil Nadu
```

Change from "AI Engineer" to "AI Engineer · Security Automation". A recruiter
screening for a security req reads the title line before anything else.

---

## SUMMARY

> AI engineer who builds agent harnesses, not chatbots. At Xavier AI, shipped an
> LLM-driven Actions layer and a Qdrant RAG pipeline into a live product with 160
> paying customers, and hardened 10+ production Lambda APIs with least-privilege
> IAM behind a cross-tenant-isolation test suite CI-gated on every merge. Builds
> the trust layer too: a red-team harness that cut prompt-injection success from
> 80% to 9%, and Pramaan — a Claude Agent SDK harness that triages Semgrep
> findings, drafts remediation PRs, and refuses to open one until the exploit is
> proven blocked.

Every clause maps to a JD line: agent harnesses (R3), production ownership,
security hardening (skill 3), evals/red-teaming (R4), remediation + proof-of-fix (R5).

---

## TECHNICAL SKILLS

```
Languages          Python, TypeScript, Rust
Agents & LLM       Claude Code, Claude Agent SDK (hooks, permission modes, subagents,
                   in-process MCP servers), Model Context Protocol, JSON-schema structured
                   output, tool-use design, GPT-5-family, LangChain
Evals & Guardrails Eval-set design, hand-labelling rubrics + inter-rater kappa, confidence
                   calibration (reliability diagrams, ECE), LLM-as-judge calibration,
                   red-teaming (OWASP LLM Top 10), RAGAS, pytest, OpenTelemetry (GenAI conventions)
Security           Semgrep (SAST), Trivy, Checkov (IaC), SARIF, DefectDojo, CWE / CVSS / SSVC,
                   threat modelling, least-privilege IAM, Linux sandboxing (namespaces,
                   cgroups v2, seccomp-bpf), PCI DSS remediation clocks
Backend & Cloud    FastAPI, Node.js, REST APIs, AWS (Lambda, IAM, VPC, API Gateway), Cloudflare
                   Workers, PostgreSQL, pgvector, Qdrant, Docker, Git, CI/CD (GitHub Actions)
```

- The **Security** row is new and is the single highest-value edit. It did not
  exist on any of the three resumes.
- Only list **Terraform** if the Pramaan build actually ships a TF module scanned
  by Checkov. It is a "plus" in the JD — worth one true line, worthless as a bluff.
- Drop the Frontend row entirely. It costs a line and buys nothing here.

---

## EXPERIENCE

**Software Developer, Xavier AI — Remote (Portugal)** · Feb 2025 – Present · beta.xavier.ai

1. Built an LLM-driven Actions system on GPT-5-mini that reads document context to
   select the right SaaS connector and emit one-click contextual actions across 10+
   integrations — structured tool-routing in production for 2,000+ users and 160
   paying customers.
2. Refactored 10+ production AWS Lambda APIs — VPC placement, least-privilege IAM,
   CORS hardening, input validation — cutting average response time 50–70%
   (45–50s → under 10s).  *(pulled from the Backend resume)*
3. Built a security-first integration test suite (94 tests across the Hono/oRPC
   stack) covering cross-tenant data isolation, revoked-credential propagation, and
   fan-out partial-failure handling — CI-gated on every merge.  *(pulled from the Backend resume)*
4. Implemented a RAG pipeline over 20,000+ records on Qdrant, cutting the full
   retrieve-and-generate path from a 45s cold start to sub-7s; deployed 35+ Lambdas
   owning each end-to-end.  *(merge of two old bullets to buy a line)*

Bullet 1 reframed from "recommends a connector" to "structured tool-routing" —
same work, JD vocabulary.

---

## PROJECTS

### Pramaan — Evidence-gated vulnerability triage & remediation harness (Claude Agent SDK)
`github.com/Melvin0070/pramaan` · public trust report

1. Built an end-to-end harness that ingests Semgrep/Trivy SARIF from live open-source
   payment repos, triages each finding to a JSON-schema verdict (TP/FP, CWE,
   reachability, payment-path and PCI-scope business impact, SSVC decision), resolves
   owners from CODEOWNERS then git blame, and files to a DefectDojo system of record
   with PCI DSS / RBI SLA clocks.
2. Encoded act-vs-escalate as configuration, not prose: a read-only triage agent with
   no Bash and `setting_sources=[]` so a scanned repo's own `CLAUDE.md` cannot instruct
   it, a fixer confined to a sandboxed git worktree behind `PreToolUse` deny hooks and
   per-run turn/budget caps, and a hard escalate-only rule for PCI-scope, KYC,
   settlement, and auth code.
3. Gated every draft PR on a deterministic proof-of-fix bundle — PoC exploit passes
   pre-patch and fails post-patch, rescan clean, tests green, no new suppression
   comments or out-of-scope files — plus a fresh-context adversarial reviewer that
   reads but never writes: `<N>` fixes drafted, `<M>` proven, funnel published per stage.
4. Shipped the eval suite behind it: `<N>` hand-labelled findings against a written
   rubric with a second rater (weighted kappa `<k>`), a reliability diagram that
   *derives* the auto-close confidence threshold rather than guessing it (ECE `<e>`),
   miss rate weighted at 4x a needless review, pass^5 consistency `<p>`, and
   prompt-injection attack success rate reported per channel across `<N>` planted
   payloads — all CI-gated.

If you need the line back, merge 3 and 4 — but keep the words *proof-of-fix*,
*calibration*, and *injection ASR*. Those are the three the JD's R4/R5 bullets ask for
and that Razorpay's own June 2026 engineering post admits are unsolved.

### LeakProof — Marketplace settlement leakage auditor (Razorpay AI Buildathon, Track 04)
`github.com/Melvin0070/leakproof`

1. Reconciliation agent over marketplace settlement data built on a deterministic-money /
   probabilistic-language split: the LLM parses, classifies, and drafts narrative, but
   never computes a rupee amount and never files a claim — every figure traces to a
   source row, every action lands in an append-only audit trail, every claim is
   human-approved.
2. `<one measured outcome — e.g. surfaced <N> leakage exceptions worth <amount> across
   <N> settlement rows, with <N>% precision against hand-reconciled ground truth>`

Put this *second*, not last. It is a Razorpay-run event and the trust discipline is the
same one the JD asks for — it corroborates Pramaan rather than repeating it.

### Proofhouse — Agentic RAG reliability scorecard & red-team gauntlet
`github.com/Melvin0070/proofhouse`

1. Four-axis reliability harness scoring agentic RAG on retrieval quality, grounding and
   citation attribution, prompt-injection resistance (OWASP LLM01), and cost/latency over
   a LangGraph retrieve-to-generate agent, instrumented with OpenTelemetry GenAI-convention
   tracing across a run/case/scorer/judge span tree.
2. Specified a deterministic canary-oracle injection scorer (exact match on marker strings
   and tool-call targets) over ~30–40 attacks seeded from OWASP LLM01 and garak/PyRIT probe
   taxonomies, keeping the security signal independent of LLM-as-judge quality.

Cut the third bullet (the confidence-gated router). Pramaan now carries the calibration story.

### Amberfork — Agent trajectory diff & regression attribution
`github.com/Melvin0070/amberfork` · crates.io

1. Rust CLI localizing regressions in agent execution traces via affine-gap
   Needleman–Wunsch alignment; validated on a pre-registered controlled-injection
   benchmark with a frozen scoring config and seeded dev/test split — 49% exact-step and
   91% within-3-step localization on a held-out 35-pair set vs. 0% exact for the strongest
   positional-diff baseline, non-overlapping 95% CIs.

One bullet. It shows benchmark rigour, which is the only thing it needs to show here.

---

## EDUCATION & CERTIFICATIONS

```
BCA, Kalvium / University of Mysore — CGPA 8.36/10          Expected Aug 2027
Class XII CBSE 83.2% (2023) · Class X CBSE 88.2% (2021)

Building with the Claude API — Anthropic, 2026
Model Context Protocol: Introduction — Anthropic, 2026
```

Keep both Anthropic certs. For this specific req they are worth more than the
Google Cloud one — the JD names Claude Code and the Agent SDK by name.

---

## Fixes to carry across all four resumes

- `Playright` → `Playwright` (Backend + Frontend skills rows)
- `Qdran` → `Qdrant` (Backend, Databases row — truncated)
- `EMade a live collaborative surface...` → `Made` (Frontend, Reprise bullet 3)
- Reprise bullets 1 and 4 on the Frontend resume are the same sentence twice
- Proofhouse bullet 2 on the AI resume ends `...calibration gate..` (double period)
- `id.` / `_` line-break artifact in the Backend Reprise bullet (`submission_id`)

---

## The two real gaps, and what to do about each

**1. SIEM / EDR / DAST — the only JD skill line you cannot currently claim.**
Semgrep and Trivy give you SAST and SCA honestly; Checkov gives you IaC. SIEM is
absent. Cheapest truthful fix: add a second ingest path to Pramaan that reads a
detection-alert corpus (Sigma rules against Wazuh or Elastic sample data) through
the *same* normaliser and triage schema. One extra Finding source, maybe a day's
work, and it converts "exposure to security tooling" from aspiration into a line
you can defend in an interview. Do not add it if it will not be built — an
unbacked SIEM claim in a security interview is worse than the gap.

**2. Every Pramaan number is currently unmeasured.**
The build order that unblocks the most resume text, cheapest first:
   1. Ingest + normalise + triage to schema on one repo — unblocks bullet 1.
   2. Hand-label 120–150 findings with a written rubric — unblocks precision,
      recall, miss rate, and kappa. This is the long pole; start it early.
   3. Calibration curve over the labelled set — unblocks ECE and the derived
      threshold. This is the single most distinctive number on the page.
   4. Injection corpus, per channel — unblocks ASR.
   5. Fixer + proof-of-fix funnel — unblocks the drafted/proven counts.
   Steps 1–4 alone carry three of the four Pramaan bullets. If time runs out,
   ship the trust report without the fixer and say so in the README.

---

## Beyond the resume

- Pin `pramaan` and `leakproof` on your GitHub profile, in that order.
- The trust report needs to be readable in 90 seconds by someone who will not clone
  the repo — funnel chart, calibration curve, per-channel ASR table, and the
  "what I got wrong" section from TODOS.md item 3.
- Keep the blog reference out of the resume and put it in the cover letter or the
  application's free-text field: their June 2026 post publishes an 85% auto-remediation
  confidence gate and a "Manual TP rate" baseline it admits was fatigue-inconsistent.
  One sentence saying Pramaan measures whether 85% means 85% is worth more than any
  resume bullet, and it proves you read what they shipped.
