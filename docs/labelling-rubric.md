# Labelling rubric — `data/corpus/labels.csv`

This rubric exists to make one rater's calls **reproducible by that same rater**, not
just defensible in the moment. D18 measures intra-rater agreement with a >=7-day
wash-out between passes: the two passes are only comparable if the *procedure* was held
constant, not just the labeller. Fatigue-driven inconsistency is the thing Razorpay's own
post admits to and the thing this project measures — a rubric that lets two readings of
the same finding land on different answers for reasons other than genuine ambiguity
defeats the point before the first pass starts.

Read this in full before labelling pass 1. Do not re-read your own `labels.csv` from
pass 1 before starting pass 2 — that would reintroduce the memory effect the wash-out is
designed to remove. If you catch yourself recalling a specific finding anyway, say so in
that row's `notes` rather than pretending the wash-out was clean; a logged memory effect
is data, an unlogged one is a silent invalidation of the whole measurement.

## The three labels

- **`true_positive`** — the flagged sink genuinely lacks the specific mitigation the rule
  checks for, in the code at the pinned `commit_sha`, *and* the flagged code path is
  reachable (defined below). Label is about correctness of the flag, not how bad it is —
  severity/exploitability is a separate judgement the schema already carries in
  `severity_reported`/`cwe`; don't fold it into this decision.
- **`false_positive`** — the mitigation is present but invisible to Semgrep's matcher
  (an escaping helper, a parameterised query, a value that only looks tainted), or the
  matched variable was never attacker-influenced in the first place.
- **`needs_human`** — you cannot resolve reachability or mitigation-presence from the
  finding plus one hop of reading, or resolving it needs information this repo doesn't
  contain (see the fixed list of reasons below). This is not a third severity tier; it
  is "I could not respond responsibly in the time available," and it must say why.

## Procedure, every time, in order

1. **Read the code, not just the snippet.** `Finding.snippet` is truncated at 500
   characters and some rules in this corpus (`echoed-request`) report a range spanning
   dozens of lines — the stored snippet is enough to triage, not enough to label. Check
   out `commit_sha` (already pinned per finding, so the code will not have moved under
   you) and open `path` at `line_start:line_end` plus the surrounding function.
2. **Identify the sink category.** This corpus has three: HTML-attribute output
   (`var-in-href`, `unquoted-attribute-var`), raw echo of request data
   (`echoed-request`), SQL string construction (`tainted-sql-string`), plus one that
   isn't a taint question at all: TLS verification configuration
   (`curl-ssl-verifypeer-off`) — see its own section below.
3. **Trace the value to its origin.** `$_GET`/`$_POST`/`$_REQUEST`/`$_SERVER`? A
   database read? A framework helper (`$this->url->link(...)`, an ORM accessor)? A
   hardcoded constant? Semgrep's rules here are syntactic-to-shallow-taint; they flag the
   *shape* of the sink, not proof that the value is attacker-controlled.
4. **Check reachability** (see definition below).
5. **Check for an out-of-band mitigation** the rule can't see: an escaping call, a bound
   query parameter, a cast to `int`, a value drawn from a fixed enum rather than input.
6. **Decide.** If 3-5 all resolved with reasonable confidence: `true_positive` or
   `false_positive`. If any step didn't resolve: `needs_human`, with the specific reason
   in `notes`.
7. **Time-box it.** Aim for under 10 minutes per finding. A 2-minute call and a
   45-minute call on the same finding a week apart are themselves a source of
   disagreement independent of the finding's actual ambiguity — if you're still unsure
   past the time-box, that's a `needs_human`, not a reason to keep digging.

## "Reachable," precisely

Reachable means: an unauthenticated user, or a user holding the **lowest-privilege
authenticated role the application defines**, can drive execution to this code with
attacker-influenced input via normal request handling (an HTTP request, a webhook, an
admin action a low-privilege user can trigger) — without first needing a *different*
vulnerability to get there.

Not reachable: dead/unreferenced code; code that only runs under a CLI/test/fixture
harness; a value that shares a request array key with attacker input but is
unconditionally overwritten by trusted backend code before the sink.

**"Admin-only" is not automatically "not reachable."** These repos are e-commerce
plugins (OpenCart, PrestaShop, Magento, WooCommerce, WordPress) whose "admin" is a
store owner — not Razorpay infrastructure, not a vetted operator. Treat a store-admin
panel as reachable, for two concrete reasons: store-owner credentials get
phished/stuffed routinely (they are not a security-sophisticated population), and a
stored payload set by one admin can execute against *other* staff viewing the same
page, which crosses a real privilege boundary even within "admin." Label
`true_positive` on that basis — but if the injected value can only ever be set by the
same admin who then views it (a single-admin settings field, no shared/stored view),
note "self-XSS, narrow blast radius" rather than downgrading to `false_positive`: the
tool caught something real, it's just low-severity, and severity is
`severity_reported`'s job, not this label's.

**Worked example — likely false positive, `var-in-href`.**
`razorpay-opencart`, `admin/view/template/payment/razorpay.twig:9`:
`<a href="{{ cancel }}" ...>`. Rule fires on any `{{ var }}` inside `href=` — purely
syntactic, no taint check. Trace `cancel`: `admin/controller/payment/razorpay.php:115`
sets `$data['cancel'] = $this->url->link('marketplace/extension', 'user_token=' .
$this->session->data['user_token'] . '&type=payment', 'SSL')` — a same-origin URL the
controller builds from the admin's own session token, never from request input. No
attacker-controlled data reaches this sink. This is the shape of most `var-in-href`
findings in this corpus: the rule earns its 94%-of-CWE-79 share by matching template
syntax, and the actual TP/FP split depends entirely on tracing each `cancel`/`link`/
`url`-style variable back to its controller. Don't label the whole rule family by this
one example — trace each one.

## When the sink is a WordPress escaping function

Relevant to every `payment-button-*-plugin`, `subscription-button-*-plugin`, and
`razorpay-woocommerce` finding. Know the difference between these before labelling any
of them:

- **Output escapers** (context-specific, applied *at the sink*): `esc_html()` for text
  content, `esc_attr()` for a generic HTML attribute, `esc_url()` for a URL going into
  `href`/`src`, `esc_js()` for a JS string literal, `wp_kses()`/`wp_kses_post()` for
  HTML you intentionally allow a subset of.
- **Input sanitisers** (applied at intake, not output): `sanitize_text_field()`,
  `absint()`/`intval()`. These are not a substitute for output escaping — they narrow
  what a value can contain, they don't make it safe for every context it's later
  echoed into.

Decision rule: `false_positive` requires the *exact flagged expression* to be wrapped in
the output escaper matching its actual context — `esc_attr()` inside a generic
attribute, `esc_url()` (not `esc_html()`) inside `href=`/`src=`. Wrong-context escaping
(`esc_html()` used inside `href=""`) is a real, recurring WordPress-plugin bug pattern,
not a mitigation — label `true_positive`. A sanitiser alone (`sanitize_text_field()`
called somewhere upstream, no output escaping at the sink) is also `true_positive` —
note in `notes` that input sanitisation without output escaping is not treated as a
mitigation here, so the same call doesn't need re-litigating on every row.

**A wide taint range is not one verdict — it's one per interpolation.**
`echoed-request` reports a single finding spanning a whole `echo` block, sometimes 20+
lines. `payment-button-wordpress-plugin`,
`templates/razorpay-button-view-templates.php:42-69` is a concrete case: nearly every
interpolated value in that block — `esc_url($previous_page_url)`,
`esc_html($button_detail['title'])`, `esc_html($button_detail['status'])`, five more —
is correctly escaped for its context. But the same block ends with
`$button_detail['html_content_item']` echoed **raw**, no escaping at all, in both
branches of the surrounding `if`. One finding row, one label: if even one interpolation
in the flagged range is unescaped for its context, the row is `true_positive` — name the
specific unescaped expression in `notes` (don't make the next rater re-derive it). Only
label `false_positive` if *every* dynamic value in the full flagged range is correctly
escaped for where it lands.

## `curl-ssl-verifypeer-off` — not a taint question

All four occurrences of this rule in the corpus are inside vendored copies of the same
third-party HTTP client (`rmccue/Requests`, versions 1.6.1-1.8.0) bundled under each
plugin's own `-sdk/libs/` directory, at the same pattern: verification is disabled only
inside `if ($options['verify'] === false) { curl_setopt(..., CURLOPT_SSL_VERIFYPEER, 0);
}` — opt-out, not default-off. No reachability tracing applies; instead, grep the
*calling* plugin code (not the vendored library) for anywhere it constructs that HTTP
client with `verify => false`. `razorpay-arastta` is a confirmed example: nothing outside
`Requests-1.7.0/` in that repo ever sets `verify`, so the dangerous branch is present but
never exercised by Razorpay's own integration code — `false_positive`, noted as "opt-out
branch, never called with verify=false by this repo's own code." If you find a real call
site passing `verify => false` (or the equivalent constant `false`), or can't rule one
out within the time-box, treat it as reachable and in-scope respectively.

## `tainted-sql-string`

The flagged line is sometimes the string *assignment*, not the query *execution* — check
where the built string is actually passed. `false_positive` if the execution call is a
parameterised/prepared statement (`PDO::prepare` + bound params, `mysqli` with bound
params) and the flagged string never reaches raw SQL text. `true_positive` if the
tainted value is concatenated or interpolated directly into the SQL text passed to
`query()`/`exec()`/equivalent.

## `needs_human` — specific triggers, and a fixed vocabulary for `notes`

Stop and use this label when:

- **`reachability-unclear`** — resolving reachability needs Razorpay-internal deployment
  or business context this public repo can't answer (e.g. "is this legacy plugin still
  installed by active merchants").
- **`mitigation-unclear`** — the taint trace runs through a framework/library call whose
  own internals live outside this repo. Cap investigation at **one hop** past the
  flagged file; if resolving needs a second hop into an out-of-corpus dependency, stop
  here rather than guessing.
- **`out-of-corpus-dependency`** — same as above, named separately for when the blocker
  is specifically "the answer lives in a repo not in this corpus" rather than general
  unclarity.
- **`time-boxed`** — you hit the ~10-minute mark without resolving it.

Always write one of these four in `notes`, plus a sentence of specifics. A `needs_human`
row with an empty `notes` field is not more efficient, it's unauditable — it looks
identical to a rater who gave up for no reason, and a week later even the same rater
won't be able to tell those apart.

## `confidence` column

This is **your** confidence in the label you just gave — not Semgrep's own
`metadata.confidence`/`impact`/`likelihood` fields, which describe the rule author's
confidence in the rule and are a completely different axis (don't transcribe them here).
Use a 1-5 scale:

1. Guess — evidence was thin, could easily be wrong.
2. Low — leaning one way, real doubt remains.
3. Medium — reasonably confident, one loose end.
4. High — confident, would defend it if challenged.
5. Certain — verified end-to-end (traced source to sink, confirmed mitigation
   present/absent by reading the actual code, no assumptions).

A `needs_human` row should almost never carry a 4 or 5 — if you were that confident,
you'd have given a real label.

## Known corpus quirks (read before you start, not after you're confused)

- **`metadata.dup_count`** — if present, Semgrep reported the same defect more than
  once at the same line; the surviving row is the earliest. Informational only. Note
  this is *not* the case of two identical lines at different points in one file: those
  are two distinct defects and each gets its own row and its own label, because a patch
  to one does not fix the other.
- **Two repos vendor the same file, and both copies are in the corpus.**
  `payment-button-siteorigin-plugin` and `payment-button-visual-composer` ship a
  byte-identical `templates/razorpay-button-view-templates.php`, so the same rule fires
  at the same six lines in both. These used to share a `finding_id` — a schema defect
  this corpus surfaced, since fixed by adding `repo` to `make_finding_id`, so the ids
  are now distinct. **Label both independently.** They are different code in different
  repos and can legitimately get different verdicts even though the snippet is
  identical; labelling the second by copying the first is the failure mode here.
- **Snippets can be truncated.** `metadata.snippet_truncated = true` means the stored
  snippet was cut at 500 characters; `metadata.snippet_full_line_count` gives the real
  span. Always open the actual file for anything wider than a one-liner — this is most
  of the `echoed-request` findings.

## Filling in `labels.csv`

Columns: `finding_id,label,confidence,rater,labelled_at,notes`. `rater` is your name or
initials, consistent across both passes. `labelled_at` is an ISO-8601 timestamp
(`date -u +%FT%TZ`), filled in at the moment you commit to a label for that row, not
backfilled at the end of a session — per-row timestamps are the evidence a wash-out
actually happened, and batch-filling them after the fact would quietly destroy that
evidence. Leave `label` blank and move on (don't leave a half-written guess) if you're
interrupted mid-row.
