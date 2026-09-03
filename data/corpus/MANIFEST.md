# Corpus manifest

Reproduction of the day-0 spike (`PROJECT-BRAINSTORM.md`, "Day-0 spike — measured, not
assumed"). The spike's raw output was lost; this run regenerates it from scratch and
persists everything this time. Run on **2026-09-03** (spike was 2026-09-02).

- **Semgrep 1.176.0**, installed via `uvx semgrep` (not added to `pyproject.toml` — it's
  a tool invocation, not a library dependency).
- **Rulesets:** `p/php` `p/security-audit` `p/xss` `p/secrets`, all four passed to a
  single `semgrep scan` invocation per repo (`--config p/php --config p/security-audit
  --config p/xss --config p/secrets --json`). 324 community rules loaded; 63 actually
  ran per repo (language/file-type prefiltering).
- **Scan wall-clock:** 16 of 25 repos completed in 47.7s (cold — first invocation also
  paid the one-time registry rule download). One invocation (`razorpay-php-testapp`)
  then stalled past 10 minutes and was interrupted; resumed cleanly and that repo plus
  the remaining 8 completed in 26.4s total on retry with a warm rule cache. See
  "Divergence from the recorded spike" below — this reads as a transient network stall
  against the Semgrep registry/telemetry endpoint (through the sandbox's filtering
  proxy), not a real performance problem: the same repo scanned fast both immediately
  before and immediately after the stall.
- **Raw Semgrep JSON** per repo: `data/raw/<repo>.json` (gitignored, reproducible from
  this manifest's commit SHAs).
- **Normaliser:** `scripts/build_corpus.py`, run via
  `uv run --python 3.12 --with jsonschema python3 scripts/build_corpus.py`. Every row is
  validated against `FINDING_SCHEMA` from `pramaan/schemas/finding.py` before being
  written.

## Repo selection

`gh repo list razorpay --limit 200 --json name,primaryLanguage,isFork,isArchived,url`,
filtered to `isFork == false && isArchived == false && primaryLanguage.name == "PHP"`.
The org has 177 public repos total (confirmed against `gh api orgs/razorpay
--jq .public_repos`, so the `--limit 200` call is not truncated); **25** pass the filter,
against the spike's recorded 24 — see divergence note below. Shallow-cloned
(`git clone --depth 1`) into `targets/` (gitignored). Total working-tree size: **37 MB**
(`du -sh targets/`), matching the spike's recorded size exactly despite the repo-count
difference.

| repo | commit SHA (HEAD at clone time) | raw findings |
|---|---|---|
| drupal_commerce_razorpay | e5d6fbf34679fbde604e02b878c29c5f9f1057e5 | 0 |
| lqext | a75f5f87617ce1a1e279f40897820a149057acaa | 0 |
| omnipay-razorpay | b716d4169cfdefce396648159c23e5e05b471f7f | 0 |
| payment-button-elementor-plugin | 9314aea62265ce5459ba3a175b46f6b82f1e8653 | 1 |
| payment-button-siteorigin-plugin | 5949912646c9cfcc60c242ddeee3b1c50544a24f | 6 |
| payment-button-visual-composer | fa4ef466dd85be8597ddacbc7d33e194da638ab6 | 6 |
| payment-button-wordpress-plugin | 57fe40b7b3c31da4bdb4acb1b0e88b6196241248 | 3 |
| payment_button_drupal_plugin | 5e71253394d4f58615e522b97bf7e2ef7afa6a7d | 0 |
| razorpay-arastta | e454c245b6cd0c6eebf2c7a147e1c2e4b21c26fc | 1 |
| razorpay-cscart | d04090b48a73bef106962918abcab70a5a964f7b | 0 |
| razorpay-edd | 1f5b6b199764a1095a9f5499988e4560f2e9a5b1 | 0 |
| razorpay-gravity-forms | 7427b6efb7d0a7bb1804a9672a3b4cc81b08634f | 0 |
| razorpay-magento | 29ab07e3aba3810cb243f27c2eb2caf35815f7d5 | 0 |
| razorpay-magento-v1 | 2c66a0f540c01720cdb9f20b16f8b9abd56fbc1f | 0 |
| razorpay-opencart | b267c0d9348ec6cda6eaf9d1b81d7f15ac005a72 | 74 |
| razorpay-php | 5db430659870e4232040142c6be2820971170fce | 0 |
| razorpay-php-testapp | 7313edc33506da103cb010331425d588f080c92f | 2 |
| razorpay-prestashop | 296f5a345f6638796410f0f6c5f1247c4a5b97bc | 5 |
| razorpay-quick-payments | 87e447fc5e4b3556cc08928028ebb826445d4bb4 | 1 |
| razorpay-whmcs | 173ed643b1ba2a675f45986dbc39284b0c294c31 | 1 |
| razorpay-woocommerce | 4af03b1cddec1c73e18a72011556ead745f1e9f6 | 18 |
| razorpay-woocommerce-subscriptions | b985eb4343aa86d4a90e8d3c2d994d50a7175f8d | 0 |
| subscription-button-elementor-plugin | 6cddd653ae6f469a0a12a3fffe3c41f700837d02 | 1 |
| subscription-button-wordpress-plugin | 582f4a1da582034138ec32f3ff0878e24987f12c | 2 |
| subscriptions-magento-plugin | bf960bf1084ed953e7df247fc8ecee9df4bd4275 | 0 |

25 repos, 0 clone failures, 0 Semgrep scan errors across any repo.

## Counts

**Raw** (sum of Semgrep JSON `results`, before any normalisation): **121 findings** —
identical to the recorded spike.

**Shipped in `data/corpus/findings.jsonl`** (after fingerprint dedup — see "Normalisation
choices" below): **121 findings**, with zero fingerprint or `finding_id` collisions.

By repo (raw / shipped, only repos with >=1 finding):

| repo | raw | shipped |
|---|---:|---:|
| razorpay-opencart | 74 | 73 |
| razorpay-woocommerce | 18 | 18 |
| payment-button-siteorigin-plugin | 6 | 6 |
| payment-button-visual-composer | 6 | 6 |
| razorpay-prestashop | 5 | 4 |
| payment-button-wordpress-plugin | 3 | 3 |
| razorpay-php-testapp | 2 | 2 |
| subscription-button-wordpress-plugin | 2 | 2 |
| payment-button-elementor-plugin | 1 | 1 |
| razorpay-arastta | 1 | 1 |
| razorpay-quick-payments | 1 | 1 |
| razorpay-whmcs | 1 | 1 |
| subscription-button-elementor-plugin | 1 | 1 |

13 repos with findings, matching the spike. `razorpay-php` alone: **0 findings**,
matching the spike.

By rule (raw / shipped):

| rule (short name) | full check_id | CWE | raw | shipped |
|---|---|---|---:|---:|
| var-in-href | `generic.html-templates.security.var-in-href.var-in-href` | CWE-79 | 72 | 71 |
| echoed-request | `php.lang.security.injection.echoed-request.echoed-request` | CWE-79 | 40 | 39 |
| curl-ssl-verifypeer-off | `php.lang.security.curl-ssl-verifypeer-off.curl-ssl-verifypeer-off` | CWE-319 | 4 | 4 |
| tainted-sql-string | `php.lang.security.injection.tainted-sql-string.tainted-sql-string` | CWE-89 | 3 | 3 |
| unquoted-attribute-var | `generic.html-templates.security.unquoted-attribute-var.unquoted-attribute-var` | CWE-79 | 2 | 2 |

5 distinct rules, matching the spike.

By CWE (raw / shipped): CWE-79 114 / 112 (94% / 94%), CWE-319 4 / 4, CWE-89 3 / 3.

By `severity_reported` (shipped, mapped from Semgrep's native ERROR/WARNING/INFO scale —
see "Normalisation choices"): high 46 (curl-ssl-off + tainted-sql, both ERROR;
echoed-request is also ERROR), medium 73 (var-in-href + unquoted-attribute-var, both
WARNING). No INFO-severity findings in this corpus.

## Divergence from the recorded spike

**Repo count: 25 vs 24.** GitHub's `primaryLanguage` is recomputed per-push, so a
same-command rerun a day later can legitimately return a different repo set. I checked
the two `primaryLanguage: null` repos that read as PHP-shaped by name
(`payment_button_joomla_plugin`, `subscriptions-opencart-plugin`) via `gh api
repos/razorpay/<repo>/languages` — both return `{}` (genuinely empty repos, not a
misclassification), which rules out the most obvious candidate mechanism. **This
divergence has no effect on the corpus**: raw findings (121), repos-with-findings (13),
distinct rules (5), and every per-rule/per-CWE/per-top-5-repo count match the spike
exactly. Whichever repo differs between the two 24/25-repo sets must be among the 12
zero-finding repos in the table above, since the recorded spike's finding-level numbers
are otherwise reproduced exactly. I did not identify the specific repo — the spike's
surviving summary doesn't record the full 24-repo list, only aggregate counts — and
chose not to guess further than "it's zero-finding" without evidence either way.

**Scan stall on `razorpay-php-testapp` (first attempt).** 16 of 25 repos scanned in 47.7s
total; the 17th invocation then ran past the 10-minute command timeout and was killed.
On retry (rules already cached), that same repo plus the remaining 8 completed in 26.4s
combined — i.e. the repo itself is not slow. Most likely a one-off stall on a network
call the CLI makes per run (registry/telemetry) inside the sandbox's filtering proxy.
Noted rather than hidden; did not affect the results, only the wall-clock time to get
them.

## Normalisation choices (scripts/build_corpus.py)

These are choices this script made while normalising into the frozen `Finding` schema —
recorded so they're auditable, not silently baked in.

1. **Fingerprint dedup, 121 raw -> 121 shipped.** The first build of this corpus
   shipped 119. `make_fingerprint()` deliberately excludes the line number so an
   unrelated edit shifting a defect down a file does not double-count it, but that
   also meant two byte-identical vulnerable lines in one file hashed identically and
   `dedup` folded them into a single record. Two groups collided, each losing a row:
   - `razorpay-opencart`, `.../razorpay_subscription_info.twig`, `var-in-href` — two of
     seven flagged lines in that file normalise to byte-identical snippet text.
   - `razorpay-prestashop`, `razorpay/controllers/front/validation.php`,
     `echoed-request` — same pattern.

   Those are two distinct defects, not one reported twice: patching the first leaves
   the second live. Reported as a schema defect rather than absorbed here, and
   subsequently fixed in `pramaan/schemas/finding.py` by adding a per-distinct-line
   `occurrence` term to the fingerprint. All three properties now hold at once — two
   identical lines stay two findings, the same line reported twice still collapses,
   and a line shift still hits the verdict cache — pinned by regression tests in
   `tests/test_ingest.py::TestOccurrenceIndexing`. **Raw 121, shipped 121, zero
   fingerprint collisions.**

2. **Snippets are read from the cloned source, not from Semgrep's `extra.lines`.**
   Anonymous (non-`semgrep login`) scans of registry rules return the literal string
   `"requires login"` in both `extra.lines` and `extra.fingerprint` for every result —
   confirmed across all 121 raw findings. Using that literal string as fingerprint input
   would have collapsed every same-rule/same-file finding regardless of actual content.
   Instead, `read_snippet()` reads `line_start:line_end` directly from the shallow
   clone, strips it, and caps it at 500 characters (`metadata.snippet_truncated = true`
   plus `metadata.snippet_full_line_count` when a taint-mode rule's range is long — see
   `echoed-request` in `razorpay-woocommerce`, which spans up to 31 lines in one
   finding).

3. **Severity mapping.** Semgrep's native scale here is only ERROR/WARNING (no INFO
   fired). Mapped `ERROR -> high`, `WARNING -> medium`, `INFO -> info` — Semgrep has no
   native "critical," and synthesising one from `impact`+`confidence` metadata would be
   an unrequested judgement call, so this script doesn't make it.

4. **`cwe`/`owasp` extraction.** `cwe` is the first `CWE-\d+` match out of
   `metadata.cwe[0]` (Semgrep gives a one-sentence string, e.g. `"CWE-79: Improper
   Neutralization..."`; this script keeps only the code). `owasp` joins every entry in
   `metadata.owasp` with `"; "` (Semgrep lists one entry per OWASP Top-10 edition the
   rule maps to, e.g. 2017/2021/2025 — all three are kept rather than picking one).

## Schema defect found by this corpus — reported, then fixed

`make_finding_id(tool, rule_id, path, line_start)` had no `repo` argument, so it
collided whenever two repos shared a relative path, rule and line. **This was not
hypothetical — it happened here**: `payment-button-siteorigin-plugin` and
`payment-button-visual-composer` both vendor a byte-identical
`templates/razorpay-button-view-templates.php`, and both trip `echoed-request` at the
same six lines (35, 65, 70, 77, 81, 120), so six `finding_id` values were each shared by
two rows. The `fingerprint`s differed correctly (that function already took `repo`), but
`finding_id` is the store's primary key — `FindingStore.get(finding_id)` — so a global
store keyed on a colliding id would have silently dropped one of each pair.

Per `docs/CONTRACTS.md` ("`pramaan/schemas/` is ... frozen — if you believe it is wrong,
say so in your report rather than editing it"), this was reported rather than patched
around locally. `make_finding_id` now takes `repo`, and this corpus rebuilds with **zero
`finding_id` collisions**. The build script keeps the collision check as a live assertion
rather than deleting it, since that is what would catch the next one.

## Files

- `data/raw/<repo>.json` — raw Semgrep JSON, one file per scanned repo (gitignored).
- `data/corpus/findings.jsonl` — 121 `Finding` records, one JSON object per line, sorted
  by `(repo, path, line_start)`, schema-validated against `FINDING_SCHEMA`.
- `data/corpus/labels.csv` — 121 rows, header
  `finding_id,label,confidence,rater,labelled_at,notes`, `finding_id` pre-filled and
  every other column blank. Not labelled by this script — see
  `docs/labelling-rubric.md`.
