"""The disclosure gate (D17).

`docs/disclosure-policy.md` says the test that a real unfixed finding's path
never reaches the rendered HTML *is* the policy, and that the document is only
the explanation. So the central test here is not a unit test of a helper: it
renders the whole report over the real 121-finding corpus and searches the
finished string for every one of those paths.

Two things make it a serious test rather than a ceremonial one:

  * It uses the **real corpus**, not a fixture. A synthetic `src/Api.php` would
    pass a leak check that `admin/view/template/payment/razorpay.twig` fails.
  * It has a **positive control**. A leak test that would also pass against a
    renderer which emits nothing proves nothing, so the same assertions run
    against a document with a path spliced into it and must fail.
"""

from __future__ import annotations

import json

import pytest
from report_fixtures import (
    STAMP,
    full_proof_bundle,
    partial_proof_bundle,
    real_corpus,
    synthetic_finding,
)

from pramaan.report import trust_report
from pramaan.report.redaction import (
    MIN_TOKEN_LEN,
    REDACTED,
    SYNTHETIC_TARGET_ALLOWLIST,
    DisclosureViolation,
    build_ledger,
    classify,
    find_secrets,
    is_synthetic_target,
    normalise_repo,
    path_tokens,
    scan,
    scrub_secrets,
    token_hash,
)
from pramaan.report.trust_report import ReportInputs, render
from pramaan.schemas import Finding


# --------------------------------------------------------------------------- #
# The test that is the policy
# --------------------------------------------------------------------------- #

def _report_over_real_corpus(**overrides) -> tuple[str, list[Finding]]:
    corpus = real_corpus()
    kwargs = {
        "findings": corpus,
        # Twelve real findings carry a partial-proof bundle (D4). A proven fix on
        # a real repository is still aggregate-only: the allowlist condition is
        # independent of the funnel condition, and this is where that matters.
        "bundles": [partial_proof_bundle(f.finding_id) for f in corpus[:12]],
        "generated_at": STAMP,
        "commit_sha": "0f1e2d3c",
        "model_id": "claude-sonnet-5",
        "corpus_labelled": False,
    }
    kwargs.update(overrides)
    return render(ReportInputs(**kwargs)), corpus


def test_no_real_finding_path_reaches_the_rendered_html():
    """The policy. Every path, every basename, every finding id, every snippet.

    Searched case-insensitively over the entire finished document — which
    covers chart labels, SVG `<title>` elements, `data-` attributes, HTML
    comments and anything else, because all of them are substrings of it.
    """
    document, corpus = _report_over_real_corpus()
    hay = document.lower()

    assert len(corpus) == 121, "the corpus this test protects has changed size"

    leaked_paths = sorted({f.path for f in corpus if f.path.lower() in hay})
    assert not leaked_paths, f"{len(leaked_paths)} finding paths reached the HTML"

    leaked_ids = [f.finding_id for f in corpus if f.finding_id.lower() in hay]
    assert not leaked_ids, (
        "finding_id embeds the path, so publishing one publishes the other"
    )

    basenames = {f.path.rsplit("/", 1)[-1] for f in corpus}
    leaked_basenames = sorted(b for b in basenames if b.lower() in hay)
    assert not leaked_basenames, (
        f"{leaked_basenames} — a bare filename plus a line number is the same "
        "disclosure wearing a shorter name"
    )

    snippet_lines = {
        line.strip().lower()
        for f in corpus
        for line in (f.snippet or "").splitlines()
        if len(line.strip()) >= 32
    }
    assert not sorted(s for s in snippet_lines if s in hay), (
        "a line of vulnerable source reached the HTML"
    )


def test_the_leak_assertions_are_not_vacuous():
    """Positive control: the same search fires on a document that does leak.

    Without this, `test_no_real_finding_path_reaches_the_rendered_html` would
    pass against a renderer that produced an empty string.
    """
    document, corpus = _report_over_real_corpus()
    victim = corpus[0]

    spliced = document.replace(
        "</footer>", f'<span data-path="{victim.path}"></span></footer>'
    )
    hay = spliced.lower()
    assert victim.path.lower() in hay

    ledger = build_ledger(corpus)
    leaks = scan(spliced, ledger)
    assert leaks, "the scanner must catch a path hidden in a data- attribute"
    with pytest.raises(DisclosureViolation):
        trust_report.assert_clean(spliced, ledger)


def test_a_path_in_an_svg_title_is_caught():
    """`<title>` is the SVG accessible name and is easy to forget about."""
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    document = f"<svg><title>{corpus[3].path}</title></svg>"
    with pytest.raises(DisclosureViolation):
        trust_report.assert_clean(document, ledger)


def test_an_html_comment_is_not_a_hiding_place():
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    with pytest.raises(DisclosureViolation):
        trust_report.assert_clean(f"<!-- {corpus[7].path} -->", ledger)


def test_percent_encoded_and_backslash_paths_are_caught():
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    path = corpus[0].path
    for spelling in (
        path.replace("/", "%2F"),
        path.replace("/", "\\"),
        path.replace("/", "&#47;"),
        path.upper(),
    ):
        with pytest.raises(DisclosureViolation):
            trust_report.assert_clean(f"<p>{spelling}</p>", ledger)


def test_the_report_still_says_something():
    """A gate that publishes nothing is not a trust report.

    The aggregate content the policy explicitly permits must be present, or the
    leak test above is passing for the wrong reason.
    """
    document, corpus = _report_over_real_corpus()
    assert "razorpay-opencart" in document, "repository counts are publishable"
    assert "generic.html-templates.security.var-in-href.var-in-href" in document
    assert "CWE-79" in document
    assert str(len(corpus)) in document
    assert len(document) > 20_000


def test_violation_report_does_not_restate_the_leaked_path():
    """A CI log on a public repository is a publication channel too."""
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    victim = corpus[0]
    with pytest.raises(DisclosureViolation) as excinfo:
        trust_report.assert_clean(f"<p>{victim.path}</p>", ledger)
    message = str(excinfo.value)
    assert victim.path not in message
    assert victim.path.rsplit("/", 1)[-1] not in message
    assert token_hash(victim.path.lower()) in message


# --------------------------------------------------------------------------- #
# Classification: both conditions, independently
# --------------------------------------------------------------------------- #

def test_full_disclosure_needs_a_synthetic_target_and_a_full_proof_funnel():
    finding = synthetic_finding()
    assert classify(finding, funnel="full_proof").level == "full"
    assert classify(finding, funnel="partial_proof").level == "aggregate"
    assert classify(finding, funnel=None).level == "aggregate"


def test_a_proven_fix_on_a_real_repository_is_still_aggregate():
    """The condition that costs the project its best demo material."""
    finding = synthetic_finding(
        finding_id="semgrep:sqli:razorpay-woocommerce:includes/api.php:44",
        repo="razorpay-woocommerce",
        path="includes/api.php",
    )
    disclosure = classify(finding, funnel="full_proof")
    assert disclosure.level == "aggregate"
    assert "allowlist" in disclosure.reason


def test_an_unknown_funnel_is_treated_as_unfixed():
    finding = synthetic_finding()
    disclosure = classify(finding, funnel=None)
    assert disclosure.level == "aggregate"
    assert "could not be determined" in disclosure.reason


def test_an_unknown_repository_is_never_publishable():
    for repo in ("", "   "):
        finding = synthetic_finding(repo=repo)
        assert classify(finding, funnel="full_proof").level == "aggregate"


@pytest.mark.parametrize(
    "repo",
    [
        "razorpay-juice-shop-mirror",
        "juice-shop-fork",
        "attacker/juice-shop-copy",
        "my-owasp-benchmark",
        "benchmarks",
        "razorpay-woocommerce",
    ],
)
def test_allowlist_membership_is_exact_not_substring(repo):
    """Substring matching is how a hostile repository name gets published."""
    assert not is_synthetic_target(repo)


@pytest.mark.parametrize(
    "repo",
    [
        "juice-shop",
        "JUICE-SHOP",
        "  juice-shop  ",
        "https://github.com/bkimminich/juice-shop",
        "bkimminich/juice-shop.git",
        "owasp-benchmark",
    ],
)
def test_allowlisted_spellings_are_recognised(repo):
    assert is_synthetic_target(repo)


def test_normalise_repo_does_not_strip_the_owner():
    """`attacker/juice-shop` must not inherit the real project's entry."""
    assert normalise_repo("attacker/juice-shop") == "attacker/juice-shop"
    assert not is_synthetic_target("attacker/juice-shop")


def test_allowlist_is_only_synthetic_targets():
    for entry in SYNTHETIC_TARGET_ALLOWLIST:
        assert "razorpay" not in entry


# --------------------------------------------------------------------------- #
# The ledger
# --------------------------------------------------------------------------- #

def test_ledger_over_the_real_corpus_withholds_everything():
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    assert ledger.n_full == 0
    assert ledger.n_withheld == len(corpus) == 121
    assert ledger.withheld_paths
    assert ledger.withheld_snippets


def test_ledger_level_of_an_unseen_finding_is_aggregate():
    ledger = build_ledger([])
    assert ledger.level("anything at all") == "aggregate"
    assert not ledger.may_publish_evidence("anything at all")


def test_conflicting_bundles_fail_closed():
    """Two bundles disagreeing about a funnel is the state D4 forbids."""
    finding = synthetic_finding()
    ledger = build_ledger(
        [finding],
        bundles=[
            full_proof_bundle(finding.finding_id),
            partial_proof_bundle(finding.finding_id),
        ],
    )
    assert ledger.level(finding.finding_id) == "aggregate"
    assert any("different funnels" in note for note in ledger.notes)


def test_a_publishable_path_colliding_with_a_withheld_one_is_downgraded():
    """Fail closed, and say so, rather than fail the whole render."""
    real = Finding(
        finding_id="semgrep:xss:razorpay-opencart:catalog/view/search.js:9",
        fingerprint="fp-real",
        tool="semgrep",
        rule_id="r",
        message="m",
        severity_reported="high",
        repo="razorpay-opencart",
        path="catalog/view/search.js",
        line_start=9,
        line_end=9,
    )
    # Same basename, different directory: publishing the Juice Shop one would
    # disclose the withheld one by proxy.
    twin = synthetic_finding(path="routes/search.js")
    ledger = build_ledger(
        [real, twin], bundles=[full_proof_bundle(twin.finding_id)]
    )
    assert ledger.level(twin.finding_id) == "aggregate"
    assert any("collide" in note for note in ledger.notes)


def test_ledger_to_dict_is_publication_safe():
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    blob = json.dumps(ledger.to_dict()).lower()
    for finding in corpus:
        assert finding.path.lower() not in blob
        assert finding.finding_id.lower() not in blob


def test_disclosure_to_dict_omits_the_finding_id():
    finding = real_corpus()[0]
    payload = classify(finding, funnel=None).to_dict()
    assert "finding_id" not in payload
    assert payload["fingerprint"] == finding.fingerprint


def test_scrub_redacts_a_path_embedded_in_free_text():
    corpus = real_corpus()
    ledger = build_ledger(corpus)
    victim = corpus[0]
    text = f"validator failed on {victim.path} at line 32"
    scrubbed = ledger.scrub(text)
    assert victim.path not in scrubbed
    assert REDACTED in scrubbed


def test_path_tokens_drops_tokens_too_short_to_mean_anything():
    assert path_tokens("a.js") == frozenset()
    tokens = path_tokens("templates/razorpay-button-view-templates.php")
    assert all(len(t) >= MIN_TOKEN_LEN for t in tokens)
    assert "razorpay-button-view-templates.php" in tokens


def test_basenames_can_be_excluded_deliberately():
    tokens = path_tokens("a/b/verify.php", include_basenames=False)
    assert "verify.php" not in tokens
    assert "a/b/verify.php" in tokens


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "secret",
    [
        "ghp_" + "a" * 36,
        "sk-ant-" + "x" * 40,
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    ],
)
def test_secret_shapes_are_detected_and_scrubbed(secret):
    assert find_secrets(f"token={secret} rest")
    assert secret not in scrub_secrets(f"token={secret} rest")


def test_a_secret_in_the_document_raises():
    ledger = build_ledger([])
    with pytest.raises(DisclosureViolation) as excinfo:
        trust_report.assert_clean("<p>ghp_" + "b" * 36 + "</p>", ledger)
    assert "ghp_" not in str(excinfo.value)


def test_clean_document_passes():
    ledger = build_ledger(real_corpus())
    trust_report.assert_clean("<p>121 findings across 13 repositories</p>", ledger)
