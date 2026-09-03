# Razorpay research report (for the "Intern, Security Engineering" project)

Compiled 2026-09-02 from primary or near-primary sources. Every fact carries its URL; items that could not be confirmed are flagged **unverified**. Medium-hosted engineering.razorpay.com posts were read through a reader proxy because Medium blocks direct fetches; dates for 2026 posts come from the publication RSS feed (https://medium.com/feed/razorpay-engineering).

---

## 1. Razorpay tech stack

### Languages
- Backend hiring JDs (official Greenhouse board): "PHP, Python, Django, Golang, Java, C++" — https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4694070005 and https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4716514005
- Go is the stated technical direction: Semgrep was chosen partly for "Strong Go language support (critical for Razorpay's technical direction)" — https://engineering.razorpay.com/building-a-sast-program-at-razorpays-scale-719887fe0aec (Jul 1, 2022)
- PHP/Laravel monolith → microservices history: talk "Razorpay's journey to microservices and ensuring data consistency" (2022) and Redis Pods podcast "How Razorpay Migrated from Monolith to Microservices" (2020), both listed in https://github.com/razorpay/public-presentations
- StackShare (older, self-reported): PHP, Laravel, Python, Golang, Swift, Node.js, MySQL, Redis, Kubernetes, Docker, EC2/S3/RDS/DynamoDB/Lambda/ELB/CloudFront/Route 53, GitHub, Terraform, Ansible, Packer, Prometheus, Kibana, Elasticsearch, Splunk, New Relic, Travis CI, Slack, Zendesk, Trello — https://stackshare.io/razorpay/razorpay
- Public GitHub org language split (177 repos): PHP 40, Go 25, Java 19, JavaScript 18, TypeScript 11, Ruby 8, Python 6 (see section 4) — https://api.github.com/orgs/razorpay/repos
- Lua for Kong plugins (custom "pci-handler" plugin) — https://konghq.com/blog/pci-compliance-kong-gateway/

### Cloud
- AWS is primary; "100+ microservices on AWS", "thousands of containers", "several thousand nodes" — https://coralogix.com/case-studies/razorpay/ (Jun 7, 2025)
- EKS explicitly: Razorpay's own kubestash-v2 README ("Sync ... to Kubernetes EKS secrets", IRSA trust policy with `oidc.eks.ap-south-1.amazonaws.com`) — https://github.com/razorpay/kubestash-v2 ; "AWS EKS cluster with Cluster Auto-Scaler", spot/on-demand ASGs, 60% of prod on spot — https://engineering.razorpay.com/optimizing-cloud-economics-automatic-leap-from-on-demand-to-spot-nodes-aa0d4a7c6e36 (Jan 25, 2024)
- AWS services named in a 2026 AWS blog on Razorpay: Aurora MySQL-Compatible, Amazon MSK, S3, Athena, EMR, Kinesis, QuickSight, Redshift, Glue; scale "500 million transactions per month", "5 billion events daily" — https://aws.amazon.com/blogs/big-data/how-razorpay-built-real-time-anomaly-detection-with-amazon-msk/ (Jul 13, 2026)
- Amazon Bedrock hosts Claude for internal tools (Hermes, RCA-GPT, AIOps) — https://engineering.razorpay.com/running-hermes-at-razorpay-a-network-isolated-self-improving-second-brain-for-every-employee-f91d56bea3f1 ; https://engineering.razorpay.com/how-we-turned-5-hours-of-rca-writing-into-10-minutes-of-review-3a154e69c8ec ; https://engineering.razorpay.com/scaling-smarter-the-inside-story-of-razorpays-aiops-evolution-6a2934ef58dd
- "AWS as the primary cloud (with some workloads on Linode and on-premise)" — third-party training-site paraphrase of an SRE posting, **unverified** — https://cloudsoftsol.com/jobs/associate-site-reliability-engineer-razorpay-bengaluru-2026/

### Kubernetes / platform
- "We run all our workloads on kubernetes"; all inter-service traffic goes through ingress; Traefik 2 IngressRoute + OpenTelemetry baggage headers for per-developer routing — https://www.signadot.com/blog/how-lyft-and-razorpay-share-development-environments-with-hundreds-of-devs
- Devstack (open source "cloud on laptop"): Kubernetes 1.15+, Helm, Helmfile, Traefik 2, LocalStack, Devspace, kube-janitor, Botkube — https://github.com/razorpay/devstack and KubeCon NA 2021 talk — https://kccncna2021.sched.com/event/lV20
- Ingress: Traefik v1.7 "since our inception" → v2.9 migration; ALBs provisioned via Terraform; Route 53 weighted DNS cutover; "thousands of existing ingress resources" — https://engineering.razorpay.com/green-signal-with-traefik-v2-a-migration-journey-at-razorpay-9fe8a7411857 (Mar 6, 2024)
- API gateway: Kong Gateway (auth/authz for "a million consumers", PCI scope reduction, canary with Spinnaker) — https://konghq.com/blog/pci-compliance-kong-gateway/ (Jun 9, 2021), https://konghq.com/blog/kong-gateway-spinnaker/ (Apr 29, 2021), talk PDF listed at https://github.com/razorpay/public-presentations
- Service mesh: Istio with Envoy sidecars, PeerAuthentication mTLS (permissive→strict) and AuthorizationPolicies, adopted for "RBI tokenization framework compliance"; ~20% latency cost — https://engineering.razorpay.com/strengthening-application-security-how-razorpay-implemented-istio-service-mesh-for-mtls-and-276a8118fe64 (Dec 12, 2023). The Traefik post also mentions Linkerd; which mesh is current is **unverified**.
- Cilium in eBPF mode for kernel-level network policy (Hermes platform, 2026) — https://engineering.razorpay.com/running-hermes-at-razorpay-a-network-isolated-self-improving-second-brain-for-every-employee-f91d56bea3f1
- Kubernetes cost program ("reducing Kubernetes cost by $300,000") — https://engineering.razorpay.com/the-culture-of-cost-optimization-reducing-kubernetes-cost-by-300-000-32611cdd19d9 (Nov 17, 2023)

### IaC
- Terraform with Atlantis ("atlantis plan" PR comments), S3 encrypted state + DynamoDB locking, state isolated per AWS sub-account/team, an internal "Drift Management System (DMS) 2.0" — https://engineering.razorpay.com/enhancing-infrastructure-management-at-razorpay-with-terraform-d5a6e05768ca (Jan 30, 2025); drift post — https://engineering.razorpay.com/the-dark-side-of-terraform-drifts-chaos-and-the-headaches-they-bring-186ce3a068b6 (Apr 15, 2025); Terraform 1.0.7 upgrade guide — https://engineering.razorpay.com/elevating-your-infrastructure-a-guide-to-terraform-1-0-7-upgrade-9d6269abac1c (May 28, 2024)
- Public Terraform module: https://github.com/razorpay/terraform-aws-ssl-ciphers
- Terragrunt: no evidence (**unverified**).

### CI/CD
- GitHub Actions self-hosted runners on Kubernetes: "10,000+ GitHub Actions jobs daily", 80% on spot, 99.2% success, custom components (spot-node-metric, spot-loss-checker, rerun-failed-jobs, k8s-runner-cleanup, Flask webhook monitor exposing Prometheus metrics) — https://engineering.razorpay.com/ci-doesnt-need-on-demand-moving-our-build-pipelines-to-spot-instances-6fff1cd92ba8 (Aug 5, 2026)
- Spinnaker + Kayenta automated canary analysis with Kong (2021) — https://konghq.com/blog/kong-gateway-spinnaker/ ; a `razorpay/spinnaker` fork exists — https://github.com/razorpay/spinnaker
- Harness is "the orchestration backbone" for the AI security-triage pipelines (pipeline-as-code, cron/webhook triggers, audit trails) — https://engineering.razorpay.com/from-750-hours-to-2-hours-ai-powered-security-triage-at-razorpay-c8baeac3a1d3 (Jun 9, 2026)
- ArgoCD: named in the Senior Security Engineer–AI JD ("GitHub Actions, ArgoCD, or similar") — https://www.instahyre.com/job-426847-senior-security-engineer-ai-at-razorpay-bangalore/ ; asserted as the GitOps deploy tool only by the third-party SRE page above (**unverified**)
- Historical: Drone CI plugin forks (drone-kubernetes, drone-s3-cache), Travis, Wercker repos in the org — https://github.com/razorpay?q=drone
- Shadow-traffic deployment validation — https://engineering.razorpay.com/from-risk-to-safety-mastering-deployments-with-shadow-analysis-1e2402161083 (Aug 1, 2024)

### Observability
- Metrics: self-hosted VictoriaMetrics cluster + vmagent + Grafana; ingestion cut from ~450B to ~170B samples/day — https://engineering.razorpay.com/how-razorpay-cut-its-metrics-bill-by-62-without-losing-a-dashboard-2a7d5467df37 (Aug 24, 2026); VictoriaMetrics talk 2021 — https://hasgeek.com/bangalore-observability-meetup/march-2021/
- Logs/APM/RUM/SIEM/MDR: Coralogix ("500+ engineers using Coralogix"; recommended by consultancy Onnivation; TCO Optimizer tiers) — https://coralogix.com/case-studies/razorpay/
- Tracing: Jaeger + Prometheus in Metro's dev stack — https://github.com/razorpay/metro ; Hypertrace forks 2022–23 (archived) — https://github.com/razorpay/hypertrace-ui ; historical Sumo Logic fork (2019, archived) — https://github.com/razorpay/fluentd-kubernetes-sumologic
- Alerting/on-call: Zenduty (Oncall Agent) — https://engineering.razorpay.com/razorpay-oncall-agent-from-30-minute-investigations-to-90-second-ai-analysis-5be7bcc461a4 ; Slack/PagerDuty in the MSK anomaly pipeline — https://aws.amazon.com/blogs/big-data/how-razorpay-built-real-time-anomaly-detection-with-amazon-msk/
- Datadog: no evidence (**unverified/none found**).

### Messaging, data, databases
- Amazon MSK (Kafka) + Debezium CDC from Aurora MySQL + Kafka Streams "Harvester" + Apache Flink + ClickHouse (replaced Pinot + ThirdEye) — https://aws.amazon.com/blogs/big-data/how-razorpay-built-real-time-anomaly-detection-with-amazon-msk/
- Metro, Razorpay's open-source pub/sub "service bus" (Go; Kafka/Pulsar/Consul backends) — https://github.com/razorpay/metro
- Data platform: Spark, Delta Lake, Iceberg, S3, Trino — https://engineering.razorpay.com/how-we-refresh-razorpays-data-warehouse-10x-faster-with-graphs-and-indexes-538abc244703 (Jul 14, 2026); CDP on Spark, DynamoDB, S3, Temporal, Airflow — https://engineering.razorpay.com/turning-scattered-data-into-queryable-segments-at-scale-how-razorpay-built-its-customer-data-3937c4b012de (Jun 26, 2026); trino-gateway OSS — https://github.com/razorpay/trino-gateway ; Qdrant vector DB (RCA-GPT) — https://engineering.razorpay.com/how-we-turned-5-hours-of-rca-writing-into-10-minutes-of-review-3a154e69c8ec
- MySQL/Redis/DynamoDB per StackShare — https://stackshare.io/razorpay/razorpay

### Secrets management
- Evolution: Ansible Vault → Credstash (AWS KMS + DynamoDB) → Alohomora (Credstash wrapper) → Kubestash (Credstash → Kubernetes Secrets); kube2iam/Kiam for IAM — https://razorpay.com/blog/secret-management-razorpay/ (Jul 10, 2018)
- kubestash-v2: DynamoDB Streams → EKS secrets, IRSA, KMS decrypt — https://github.com/razorpay/kubestash-v2 ; https://github.com/razorpay/alohomora
- HashiCorp Vault used as the card tokenization service behind Kong — https://konghq.com/blog/pci-compliance-kong-gateway/
- 2026: per-user IRSA short-lived creds, no long-lived keys in pods, AES-256-GCM session cookies, image digests pinned in a private tag-immutable registry with scan-on-push, distroless bases — https://engineering.razorpay.com/running-hermes-at-razorpay-a-network-isolated-self-improving-second-brain-for-every-employee-f91d56bea3f1

### SSO / IdP, ticketing, chat, source control
- Google OIDC/Google Workspace for internal auth (Hermes gateway uses Google OIDC; Concierge uses Google OAuth via oauth2_proxy) — same Hermes post; https://github.com/razorpay/concierge. Endpoint/enterprise stack named in a JD: SentinelOne, Zscaler, Active Directory, Jamf — https://www.instahyre.com/job-426847-senior-security-engineer-ai-at-razorpay-bangalore/
- Ticketing: DevRev (AI verdicts posted to DevRev tickets) — https://engineering.razorpay.com/from-750-hours-to-2-hours-ai-powered-security-triage-at-razorpay-c8baeac3a1d3 ; "Postman, Jira, Freshdesk, DevRev" in a Solutions Engineering JD — https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4718628005
- Chat: Slack (security notifications, #ai-help, incident channels) — https://engineering.razorpay.com/secure-code-reviewer-copilot-e4f575f42591 ; https://github.com/razorpay/ai-playbook
- Source control: GitHub org, GitHub fine-grained tokens, Dependabot — https://github.com/razorpay ; https://github.com/razorpay/bhadra

### Internal platform / tool names (public)
Devstack, Metro, Bhadra (VMP), Alohomora/Kubestash (secrets), Concierge (SG/ingress leases), Citadel (docs SSG), DMS 2.0 (Terraform drift), OneDoc & Patterns (workflow platform — https://engineering.razorpay.com/simplifying-workflows-razorpays-journey-with-onedoc-patterns-part-1-30f295b1e9ad), F.R.I.D.A.Y. / Incident Prediction System / SKYSAVER (AIOps), RCA-GPT, Oncall Agent (a.k.a. Project Viveka), Bumblebee, LLM Gateway, Compass (internal Claude Code plugin marketplace — https://github.com/razorpay/ai-playbook), "AI RFC" template reviewed by a Staff+ Council (same repo, `appendices/I-templates/RFC-template.md`, pipeline in `belts/05-council/C03-rfc-pipeline.md`). A general engineering RFC process beyond that: **unverified**.

---

## 2. Security engineering public footprint

### Engineering blog posts on security
| Post | Date | Key facts |
|---|---|---|
| Kubernetes secret management — https://razorpay.com/blog/secret-management-razorpay/ | Jul 10, 2018 | Credstash/KMS/DynamoDB, Alohomora, Kubestash, encrypt etcd |
| Building a SAST program at Razorpay's scale — https://engineering.razorpay.com/building-a-sast-program-at-razorpays-scale-719887fe0aec | Jul 1, 2022 | Semgrep chosen; PR-diff scans + periodic full scans via GitHub Actions; findings as PR comments; "0 to 200 applications onboarded in a little over 12 months"; rule templating for high-confidence TPs; Security Champions program; bottom-up rollout starting in the Capital BU |
| Istio service mesh for mTLS — https://engineering.razorpay.com/strengthening-application-security-how-razorpay-implemented-istio-service-mesh-for-mtls-and-276a8118fe64 | Dec 12, 2023 | mTLS + AuthorizationPolicy for RBI tokenization compliance; PSP pain; ~20% latency |
| Secure Code Reviewer — Copilot — https://engineering.razorpay.com/secure-code-reviewer-copilot-e4f575f42591 | Jun 21, 2024 | PR → Semgrep + LLM review → Slack; GPT-4, Gemini 1.0/1.5, CodeBison tested on OWASP Juice Shop; ">75%" TP rate; Gemini $1.731 vs GPT-4 $30.958 per repo scan; crown-jewel prompts with threat-model context; human-in-the-loop (covered by tl;dr sec #240 — https://tldrsec.com/p/tldr-sec-240) |
| From 750 Hours to 2 Hours: AI-Powered Security Triage — https://engineering.razorpay.com/from-750-hours-to-2-hours-ai-powered-security-triage-at-razorpay-c8baeac3a1d3 | Jun 9, 2026 | "For every 10 alerts, 7–8 were false positives"; L1 triage (live) with "29 specialized sub-skills", "2–4 per finding" loaded progressively, ~"50K to 2.5K" tokens; generalist "~60% accuracy" vs specialized "75–80%"; "Only verdicts above 85% confidence trigger auto-remediation"; Semgrep API + GitHub fine-grained tokens; L2 remediation bot (live) opens PRs for SAST/SCA/secrets with audit logging, works backlog by criticality; L3 Semgrep rule auto-tuning "coming soon" once L1 "reaches 90%+"; Harness orchestration; verdicts to DevRev; "roughly 960x speed-up". **No validation protocol given**: accuracy is compared against a "Manual TP rate" that the post itself says had "significant fatigue-driven inconsistency". **Open problems the post names**: "How much context is enough?", "skill drift over time as edge cases accumulate", unclear path to "95%+", and cross-repo propagation ("a vulnerability in a shared SDK can silently propagate to dozens of downstream services"; "transitive context remains an open problem"). LLM vendor not named. |
| Running Hermes at Razorpay — https://engineering.razorpay.com/running-hermes-at-razorpay-a-network-isolated-self-improving-second-brain-for-every-employee-f91d56bea3f1 | Jul 12, 2026 | 220 per-employee AI agents, one namespace/volume/IRSA identity each; Cilium eBPF deny-by-default egress; CrabTrap TLS-intercepting egress proxy (Brex OSS) with "live LLM-based policy" — ~15M calls/month screened, ~219K blocked; Google OIDC; supply-chain pinning |

Adjacent: RCA-GPT (Claude on Bedrock) — https://engineering.razorpay.com/how-we-turned-5-hours-of-rca-writing-into-10-minutes-of-review-3a154e69c8ec (Mar 3, 2026); Oncall Agent (LangGraph, Coralogix/Grafana/K8s/AWS agents, Zenduty→Slack, shadow mode, 80% MTTI reduction) — https://engineering.razorpay.com/razorpay-oncall-agent-from-30-minute-investigations-to-90-second-ai-analysis-5be7bcc461a4 (Apr 29, 2026); Kong PCI scope reduction — https://konghq.com/blog/pci-compliance-kong-gateway/

### Conference talks / podcasts (attribution only)
- Nullcon Goa 2022: "Handling A Bug Bounty program From A Blue Team Perspective" — Ashwath K (Staff Engineer) & Ankit Anurag (Lead Security Engineer), Razorpay — https://archive.nullcon.net/website/goa-2022/speakers/handling-bug-bounty-program-from-blue-team-perspective.php
- c0c0n 2024 (Nov 15–16): "Automated Security Engineer Co-Pilot: Leveraging LLMs for Enhanced Code Security" — Ashwath Kumar (Head of Security) & Hariprasad Pujari; "The Stealth Code Conspiracy: Unmasking Hidden Threats in CI/CD Pipelines" — Suchith Narayan (Lead Security Engineer) — https://india.c0c0n.org/2024/speakers
- KubeCon NA 2021: Devstack talk (Srinidhi S, Venkatesan Vaidyanathan) — https://kccncna2021.sched.com/event/lV20
- Boring AppSec Podcast S1E01 "Asset Inventory" includes a talk on automating asset inventory at Razorpay (Sandesh Mysore Anand, former Razorpay Head of Security, & Satyaki) — https://boringappsec.substack.com/p/the-boring-appsec-podcast-s1e01-asset ; newsletter listed in https://github.com/razorpay/public-presentations
- Kong blog posts (2021) by Razorpay engineers on PCI/Kong and Kong+Spinnaker — URLs above. Black Hat/DEF CON/BSides/Seasides appearances: **unverified** (only LinkedIn bio claims found).

### Open-source security tooling from Razorpay
- Bhadra — "Vulnerability Management Platform" (DefectDojo-derived Django app): products = GitHub repos, engagements = tools (e.g. `bhadra_Semgrep_Scan`, `bhadra_Dependabot_Scan`), daily tests, "single glass of pane" across SAST/SCA/DAST/container scanning/CSPM, data pulled into Looker/Superset scorecards; Dockerfiles + k8s manifests — https://github.com/razorpay/bhadra
- Concierge — time-bound leases on AWS Security Groups / Kubernetes Ingress with Google OAuth — https://github.com/razorpay/concierge
- Alohomora, Kubestash, kubestash-v2 (secrets) — https://github.com/razorpay/alohomora , https://github.com/razorpay/kubestash-v2
- terraform-aws-ssl-ciphers (ELB TLS policies) — https://github.com/razorpay/terraform-aws-ssl-ciphers
- Forks signalling tooling: django-DefectDojo (archived 2023), MISP (archived 2022), cloudsploit-scans, sonarcloud-github-action, harbor, imagepullsecret-patcher, chaos-mesh, k6 — https://github.com/razorpay?q=DefectDojo etc. (org listing: https://api.github.com/orgs/razorpay/repos?per_page=100)
- SDK repos carry Dependabot config and `.semgrepignore` (razorpay-php, razorpay-node, razorpay-go); razorpay-node's latest commit is "fix/semgrep-supply-chain-override" (2026-07-21) — https://github.com/razorpay/razorpay-node

### Bug bounty
- HackerOne program: https://hackerone.com/razorpay (page is JS-rendered; bounty table and stats **not publicly verifiable**). Org profile links it as the security contact — https://github.com/razorpay/.github
- Policy snapshot (last updated 2022-05-23): in scope dashboard/api/checkout/invoices.razorpay.com; SLAs first response 5 business days, triage 10, bounty 14; header `X-Bug-Bounty: HackerOne-<username>`; no automated scanners; safe-harbor language; exclusions (missing headers, clickjacking-only, DoS, self-XSS, "price manipulation without successful transaction") — https://firebounty.com/35974-razorpay/
- Aggregator stats: reward range "$100 - $1,000", launched May 23, 2022, 6 in-scope assets — https://bbradar.io/program/HackerOne:razorpay (**unverified** amounts)
- Parallel program on BugBase (Indian platform), same SLAs, header `X-Bug-Bounty: BugBase-<username>` — https://bugbase.ai/programs/razorpay-bugbounty
- Open-source repos are out of scope but findings are routed to maintainers — https://github.com/razorpay/razorpay-mcp-server/blob/main/SECURITY.md
- Trust-portal disclosure hub — https://razorpay.com/security/disclosure/
- Example disclosed finding: QR-code IDOR leaking payer UPI/transaction data, reported via HackerOne, fixed — https://infosecwriteups.com/qr-code-idor-vulnerability-in-razorpay-af1396dbf2af

### Certifications / compliance
- PCI DSS Level 1, ISO 27001:2022, SOC 2 Type 2 — https://razorpay.com/docs/security/
- PCI DSS v4.0.1 certificate: Razorpay Software Limited, Service Provider, assessed by Ampcus Cyber, certified Sep 24, 2025, valid to Sep 23, 2026, cert 13AC-24PC-5864 — https://www.ampcuscyber.com/certificate/razorpay-pci-dss-coc.pdf
- Trust portal certifications page: PCI DSS v4.0 (2023) across Razorpay Software, RZPX, Ezetap (POS), Curlec (Malaysia); PCI 3DS, PCI PIN (Ezetap), ISO 27001, SOC 3 (2022-23), RBI/NPCI data-localization attestations, cloud configuration reviews — https://razorpay.com/security/certifications/ ; portal home shows threat-intel feeds — https://razorpay.com/security/
- RBI: final PA authorisation Dec 19, 2023 — https://www.business-standard.com/companies/news/razorpay-cashfree-receive-final-rbi-nod-for-payment-aggregator-biz-123121901296_1.html ; PA-Cross Border (Dec 2025) — https://finance.yahoo.com/news/razorpay-gains-payment-aggregator-cross-130144298.html ; PA-Physical (Jan 2026) — https://razorpay.com/newsroom/razorpay-pos-receives-rbi-approval-for-offline-payment-aggregator-licence/
- Shared responsibility model doc — https://razorpay.com/docs/security/shared-responsibility-model/

### Published incidents / lessons
- May 2022: police complaint over Rs 7.38 crore lost when "unknown hackers and fraudulent customers tampered, altered and manipulated the authorization and authentication process" so 831 failed transactions (16 merchants, Mar 6–May 13, 2022) were reported as approved; auth partner Fiserv — https://www.business-standard.com/article/companies/hackers-fraudulent-customers-stole-rs-7-38-cr-complaint-lodged-razorpay-122052001343_1.html
- Dec 2022: RBI asked Razorpay/Cashfree to pause new-merchant onboarding pending PA authorisation (regulatory, not a breach) — https://www.business-standard.com/article/companies/rbi-asks-razorpay-cashfree-to-temporarily-stop-onboarding-of-new-customers-122121600780_1.html
- Availability: ~50-minute outage Apr 7, 2026 per StatusGator — https://statusgator.com/services/razorpay ; no public data breach found for 2024–2026 (**none found**).

### Security job postings and the tools they name
| Role | Tools/tech named | Source |
|---|---|---|
| Security Engineer (SecOps, 1–4 yrs) | AWS GuardDuty, CloudTrail, Kubernetes, Python/Bash/PowerShell, alert triage, incident response, threat intel | https://www.instahyre.com/job-387010-security-engineer-at-razorpay-bangalore/ ; https://remasto.com/jobs/VGjZc2CcF1o0nby |
| Senior Cloud Security Engineer (5–8 yrs) | Kubernetes, AWS, IAM rules to "detect and remediate vulnerabilities", Terraform/CloudFormation, Python/Bash, CCSP/CKS/AWS Security Specialty, offensive cloud drills | https://portfoliojobs.tcv.com/companies/razorpay/jobs/62226027-senior-security-engineer |
| Senior Product Security Engineer (5–8 yrs) | Burp Suite, ZAP, Postman; "SAST, SCA, secrets scanning, basic DAST" in CI/CD; Python/JS/Go; STRIDE-lite; LLM attack vectors (prompt manipulation, data leakage) | https://getmereferred.com/job-listing/senior-security-engineer-razorpay-bengaluru-5-to-8-years-experience-2e1203b9-5396-4e9b-a515-e27480b4ba22 |
| Senior Security Engineer – AI (3–6 yrs) | "Claude (Anthropic API), OpenAI"; Claude Agent SDK, LangGraph, AutoGen, CrewAI; MCP servers wrapping "SentinelOne, Zscaler, AWS APIs, Active Directory, Jamf, Semgrep"; evals & guardrails; LLM gateway/model routing/observability; LiteLLM, Ollama, vLLM; EKS, Helm, Kustomize; Terraform/Pulumi/CDK; GitHub Actions/ArgoCD; SIEM/XDR SentinelOne, Splunk; CSPM Wiz, Prowler; OWASP LLM Top 10; PCI DSS, ISO 27001, SOC 2, RBI, DPDP; MITRE ATT&CK | https://www.instahyre.com/job-426847-senior-security-engineer-ai-at-razorpay-bangalore/ |
| Intern, Security Engineering | Not found on the official Greenhouse board (23 open jobs, none security-titled) or aggregators — **unverified publicly** | https://boards-api.greenhouse.io/v1/boards/razorpaysoftwareprivatelimited/jobs |

---

## 3. Razorpay + AI

### AI coding agents inside engineering
- Org-wide AI Playbook (public repo, "v0.61 alpha", 2026-08-13): belt curriculum (Foundation → White → Yellow → Green → Black → Council), "seven reusable Claude Code skill definitions" (`security-review-subagent`, `pre-ship-check`, `blade-compliance-reviewer`, `design-intel`, `production-compiler`, `setup-verify`, `playbook-course`), internal "Compass" plugin distribution, private `razorpay/claude-plugins` repo (404 publicly), Claude and Codex manifests, Cowork tenant, #ai-help Slack, AI RFC pipeline (`appendices/I-templates/RFC-template.md`, reviewed by the Staff+ Council per `belts/05-council/C03-rfc-pipeline.md`) — https://github.com/razorpay/ai-playbook ; hub https://razorpay.github.io/ai-playbook/
- `security-review-subagent` skill: fresh-context subagent runs six checks (redlines, prompt-injection capability creep, untrusted-input handling, output exposure, injection-vulnerable code shapes, unscoped capabilities), never modifies code, always cites file and line, redacts redline values to their "threat shape", escalates "PCI scope, KYC flows, and settlement code" to human review, and returns only a structured report (Branch/Base/Run at/Brief version; per-finding File/line/Risk/Suggested fix; Summary count) — https://github.com/razorpay/ai-playbook/blob/master/skills/security-review-subagent/SKILL.md
- Official JDs: "Claude Code or Cursor is your default environment… You orchestrate agents, build with skills and MCPs" (Full Stack Builder) — https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4699107005 ; "coding agents for routine PRs, knowledge agents for merchant context, and routing agents for incident triage" (Forward Deployed Engineer) — https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4723067005 ; "AI Code builders like Cursor, Claude" as a plus (SDE) — https://job-boards.greenhouse.io/razorpaysoftwareprivatelimited/jobs/4694070005 ; careers page headline "Hiring the Most Obsessed AI Builders" — https://razorpay.com/careers/
- Cursor adoption evidence: bulk ".cursorignore" commits across public repos (Apr 25 and Jul 23, 2025) — https://api.github.com/repos/razorpay/devstack/commits?path=.cursorignore ; the MCP server repo ships `.claude/skills/razorpay-mcp-tool-gen`, `AGENTS.md`, `.cursor` — https://github.com/razorpay/razorpay-mcp-server
- Internal AI systems: Hermes agents (Claude via Bedrock plus GPT/Qwen/Kimi/GLM/DeepSeek through an "LLM Gateway"), RCA-GPT (Claude on Bedrock, Qdrant), Oncall Agent (LangGraph), Bumblebee fraud agents (Python ReAct; 8,500 review hours/month → seconds; 99%+), AIOps on Bedrock — URLs in sections 1–2 and https://engineering.razorpay.com/meet-bumblebee-the-multi-agent-ai-architecture-that-changed-fraud-detection-at-razorpay-c2b6d5704f51 (Dec 17, 2025)

### Razorpay AI/agentic products and Anthropic ties
- Razorpay MCP Server (Go, open source; hosted remote option; Claude/Zapier/VS Code named) — https://github.com/razorpay/razorpay-mcp-server ; https://razorpay.com/newsroom/razorpay-becomes-indias-first-payment-gateway-to-launch-mcp-server-for-instant-ai-payment-integration/ (Apr 2025)
- Agentic Payments on ChatGPT with NPCI + OpenAI (GFF 2025; UPI Circle/Reserve Pay; Bigbasket, Vodafone Idea demos) — https://razorpay.com/blog/razorpay-unveils-agentic-payments-on-chatgpt-with-npci-indias-first-ai-powered-conversational-payment-experience/
- Agentic UPI payments on Claude with NPCI (Feb 23, 2026; Zomato/Swiggy/Zepto) — https://thepaypers.com/payments/news/razorpay-and-npci-launch-agentic-payments-on-claude
- Agent Studio "built using the Claude Agent SDK from Anthropic" + Agentic Experience Platform (Onboarding 30–45 min → ~5 min; Integration <10 min; "Integration with Claude Code for developers"); quote from Irina Ghose, MD Anthropic India — https://razorpay.com/newsroom/razorpay-launches-the-worlds-first-ai-native-agent-studio-for-payments-at-ftx26-powered-by-anthropics-claude/ (Mar 12, 2026)
- RAY AI business assistant, AI fraud engine — https://razorpay.com/newsroom/razorpay-strengthens-tech-leadership-appoints-ex-google-leader-prabu-rambadran-as-sr-vice-president-engineering/

### Leadership statements (2025–2026)
- Prabu Rambadran (ex-Google Cloud) appointed SVP Engineering to lead "AI-first" platforms (Nov 10, 2025) — URL above
- Harshil Mathur: "AI shouldn't stop at recommendations — it should finish the job" (Feb 20, 2026) — https://yourstory.com/2026/02/razorpay-harshil-mathur-ai-bets-ecommerce-conversational-mcp-agentic
- Four senior AI engineering hires (Aug 4, 2026); Shashank Kumar: software "will increasingly reason, decide, and act" — https://entrackr.com/snippets/razorpay-hires-four-senior-engineering-leaders-for-ai-roles-12227319
- AI Buildathon → AI Builder Internship (₹75,000/month, Bangalore, tracks incl. "AI Risk Manager"; judged on audit trails, exception handling, "Failure Recovery") — https://razorpay.com/buildathon/

---

## 4. GitHub org (github.com/razorpay) — public API enumeration
- 177 public repos, org created 2014-05-27, 26 public members; 75 are forks, 35 archived — https://api.github.com/orgs/razorpay ; https://api.github.com/orgs/razorpay/repos?per_page=100&page=1 (and page=2)
- Languages (primary): PHP 40, Go 25, Java 19, JavaScript 18, TypeScript 11, Ruby 8, Shell 7, HTML 6, Python 6, Objective-C 6, Lua 2, Scala 2, Dart 1, Kotlin 1, HCL 1, Swift 1
- Most starred: blade 648 (design system, TS), ifsc 393, go-financial 317, razorpay-node 243, razorpay-mcp-server 230, razorpay-php 206, razorpay-python 174, react-native-razorpay 133, devstack 133, razorpay-flutter 116, razorpay-android-sample-app 95, ifsc-api 89, concierge 75, razorpay-java 73, razorpay-ruby 66, razorpay-go 59, metro 56, razorpay-cli 50, razorpay-woocommerce 45, public-presentations 39, alohomora 32, trino-gateway 31, bhadra 16
- Most recently pushed (2026-09-01/02): blade, ifsc, ifsc-api, ai-playbook, razorpay-flutter(-customui), razorpay-pod, razorpay-customui-pod, razorpay-woocommerce, i18nify; a large batch shows 2026-08-28 (bulk org operation; not proof of activity)
- SDKs by language: PHP, Python, Node, Go, Java, Ruby, .NET (C#), Flutter (Dart), React Native, Cordova, Capacitor, iOS pods (Obj-C/Swift), Android samples (Java/Kotlin), CLI (Go), MCP server (Go), n8n node (TS)
- Commerce plugins (PHP): WooCommerce, Magento 1.x/2.x, OpenCart, PrestaShop, WHMCS, CS-Cart, Drupal Commerce, Arastta, EDD, Gravity Forms, WordPress/Elementor/SiteOrigin/Visual Composer buttons, Omnipay
- Security/infra repos: bhadra, concierge, alohomora, kubestash, kubestash-v2, terraform-aws-ssl-ciphers (only HCL repo), etcd-backup, devstack, metro/metro-proto, golib, trino-gateway/presto-gateway, and forks: cloudsploit-scans, django-DefectDojo, MISP, sonarcloud-github-action, harbor, distribution, chaos-mesh, k6, spinnaker, helmfile, helm-git, drone-kubernetes, drone-s3-cache, imagepullsecret-patcher, sqs-autoscaler-controller, statsd_exporter, status-cake-exporter, statping, hypertrace-*, kong-pongo/konga/kong-template, GitHub Action forks (checkout-action, docker-build-push-action, docker-login-action, create-comment, gh-find-current-pr, list-files-in-pr, branch-cleanup-action), proto-api-docs-action
- AI repos: razorpay-mcp-server, ai-playbook

### Scanner-demo candidates (all MIT/BSD/GPL, non-fork, real Razorpay code)
| Repo | Lang / size | Last commit | Why it's a good target |
|---|---|---|---|
| razorpay-mcp-server — https://github.com/razorpay/razorpay-mcp-server | Go 804 KB + Dockerfile, MIT, 230★ | 2026-03-26 | CI (`ci.yml`, `lint.yml`, `docker-publish.yml`) has no SAST/container scan → Semgrep Go + Trivy image/Dockerfile + govulncheck show real gaps; ships `.claude/skills` → thematically aligned |
| razorpay-php — https://github.com/razorpay/razorpay-php | PHP 388 KB, MIT, 206★ | 2026-06-11 | Has Dependabot + `.semgrepignore`, single CI workflow; Semgrep PHP + composer audit |
| razorpay-node — https://github.com/razorpay/razorpay-node | JS 197 KB, MIT, 243★ | 2026-07-21 | Publish workflow uses `NPM_TOKEN`/TOTP secrets → GitHub Actions hardening findings; Semgrep JS + npm audit |
| razorpay-woocommerce — https://github.com/razorpay/razorpay-woocommerce | PHP 1.17 MB, GPL-2.0, 45★ | 2026-07-15 (pushed 2026-09-02) | Largest PHP surface (WordPress plugin: XSS/CSRF/SQLi rule classes) |
| bhadra — https://github.com/razorpay/bhadra | Python/Django 4.4 MB + Dockerfiles, docker-compose, k8s manifests, BSD-3 | 2026-03-02 | Checkov/Trivy on IaC + Semgrep Python + pip-audit; and it is itself a VMP → natural "agent feeds Bhadra/DefectDojo" demo |
Alternates: razorpay-python (170 KB, 2026-03-09), razorpay-go (175 KB, 2026-04-24), metro (Go 955 KB, Dockerfile, 2025-09-15), concierge (Go + docker-compose, 2025-09-15), trino-gateway (Python+Go, Dockerfile, 2026-06-22), kubestash-v2 (Python + IAM policies/k8s YAML, 2025-09-15), terraform-aws-ssl-ciphers (HCL, references legacy ELB cipher policies → Checkov TLS findings). Language/commit data from https://api.github.com/repos/razorpay/{repo}/languages and …/commits?per_page=1.

---

## 5. Indian fintech regulatory controls an agent can map findings to
- **RBI Master Directions on Cyber Resilience and Digital Payment Security Controls for non-bank PSOs** (RBI/DPSS/2024-25/123, Jul 30, 2024): phased applicability — large PSOs Apr 1, 2025, medium Apr 1, 2026, small Apr 1, 2028 (para 3); SIEM correlation (16c); S-SDLC "secure by design" (17a); app security testing "source code review, VA, PT… at least on annual basis" (18a); patches "within an appropriate time frame", critical patches "immediately" (21); unusual incidents reported to RBI "within 6 hours of detection" plus CERT-In (22d); API security per recognised frameworks (24); cloud policy + annual CSP audits (26); audit logs kept ≥ 5 years (27e) — https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12715 (full text mirror: https://taxguru.in/rbi/master-directions-cyber-resilience-digital-payment-security-controls-non-bank-payment-system-operators.html)
- **RBI (Regulation of Payment Aggregators) Directions, 2025** (Sep 15, 2025; CO.DPSS.POLC.No.S-633/02-14-008/2025-26; supersedes 2020/2021 PA-PG guidelines and 2023 PA-CB): Annexure 1 §1.2 PCI-DSS/PA-DSS; §1.3 incident/CHD-breach reporting to RBI + monthly incident reports with RCA; §1.5 quarterly internal audit, annual external audit by CERT-In-empanelled auditor, "bi-annual VAPT reports", PCI AOC; §1.7 IT Steering Committee; para 9(e) cross-references the 2024 cyber MD — https://taxguru.in/rbi/rbi-regulation-payment-aggregators-directions-2025.html ; RBI press release https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx?prid=61218 ; PDF mirror https://www.fidcindia.org.in/wp-content/uploads/2025/09/RBI-PAYMENT-AGGREGATORS-DIRECTIONS-15-09-25.pdf
- Predecessor 2020 PA/PG guidelines Annex 2 (same 1.1–1.7 controls) — https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=11822&Mode=0
- Bank-side context (not applicable to a PA, but to bank partners): RBI IT Governance MD (Nov 7, 2023, effective Apr 1, 2024) — https://www.mondaq.com/india/it-and-internet/1445244/rbi-issues-master-directions-on-information-technology-governance-risk-controls-and-assurance-practices ; replaced for commercial banks by the Jul 31, 2026 Cybersecurity/Technology Risk Directions (VA every six months, annual PT) — https://www.medianama.com/2026/08/223-rbi-cybersecurity-framework-commercial-banks/
- **CERT-In Directions (Apr 28, 2022, effective 60 days later)**: report Annexure I incidents "within 6 hours of noticing"; enable and retain ICT logs "for a rolling period of 180 days… within the Indian jurisdiction"; sync clocks to NIC/NPL NTP; incident@cert-in.org.in — https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf
- **PCI DSS v4.0.1** (future-dated requirements mandatory Mar 31, 2025; Razorpay certified v4.0.1 Sep 2025): 6.3.1 identify vulns from industry sources and risk-rank (critical/high at minimum) — https://www.accessitgroup.com/understanding-and-meeting-pci-dss-requirement-6-3-1-vulnerability-identification/ ; 6.3.2 software/component inventory (SBOM) — https://www.securitymetrics.com/blog/a-guide-to-new-requirements-in-pci-dss-4-0-1 ; 6.3.3 critical/high patches within one month — https://chadmbarr.com/vulnerability-management-and-pci-dss-unraveling-requirement-6-3-1/ ; 6.4.3 payment-page script inventory/authorization/integrity and 11.6.1 change-detection (weekly or per TRA) — https://www.feroot.com/blog/pci-dss-4-0-1-requirement-6-4-3-and-11-6-1/ , https://blog.pcisecuritystandards.org/new-information-supplement-payment-page-security-and-preventing-e-skimming ; 10.4.1.1 automated log review (SIEM) — securitymetrics link above; 11.3.1 internal scans every three months with high/critical resolved and rescanned, 11.3.1.1 lower-risk vulns per targeted risk analysis, 11.3.1.2 authenticated scans, 11.3.2 quarterly ASV scans — https://www.serverscan.com/scanning-requirements-explained , https://linfordco.com/blog/pci-dss-4-0-requirements-guide/ ; 11.4.x internal/external pentest at least every 12 months and after significant change, 11.4.4 exploitable findings corrected and retested — https://www.stingrai.io/blog/pci-dss-penetration-testing-2026 ; 12.3.1 targeted risk analysis inputs (11.3.1.1, 11.6.1, 12.10.4.1) — linfordco link
- **DPDP Act 2023 + Rules 2025**: s.8(5) reasonable security safeguards (penalty up to ₹250 crore), s.8(6) breach notification (up to ₹200 crore) — https://www.tcsa.in/frameworks/dpdp/penalties-enforcement ; Rules notified Nov 13, 2025, Rule 7: notify affected Data Principals and the Board "without delay", detailed report to the Board "within seventy-two hours" (extendable on written request) with cause, impact, mitigation, and responsible-person findings — https://www.dpdpa.com/dpdparules/rule7.html , https://www.medianama.com/2025/11/223-data-breach-reporting-timeline-of-dpdp-rules-2025-explained/

---

## Signals worth building around (from the evidence above)
- Razorpay already runs Semgrep → LLM triage (29 sub-skills, 75–80% accuracy, 85% confidence gate, Harness pipelines, DevRev tickets) and has a public DefectDojo-based VMP (Bhadra); a project that reproduces this loop on their own OSS repos, with explicit evals against a labelled finding set and confidence-gated automation, speaks their language directly.
- Their own `security-review-subagent` skill defines the review contract they expect (fresh-context subagent, cite file:line, never edit, redact secrets, escalate PCI/KYC/settlement paths).
- Controls to map findings to: RBI 2024 MD paras 18(a)/21/22(d)/27(e), PA Directions 2025 Annex 1 §1.3/§1.5, PCI DSS 6.3.1/6.3.3/11.3.1(.1)/11.4.4/6.4.3/11.6.1, CERT-In 6h/180d, DPDP Rule 7 72h.
- Stack to target in a demo: GitHub Actions on Kubernetes/EKS, Terraform+Atlantis, Semgrep, Dependabot, Trivy-style container scanning (they pin digests/scan-on-push), Coralogix SIEM with GuardDuty/CloudTrail/WAF, Slack + DevRev/Jira, Claude on Bedrock.
