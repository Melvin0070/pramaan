"""Tests for the deterministic path tagger.

Every path asserted here is a real file in razorpay/razorpay-woocommerce,
razorpay/razorpay-php, razorpay/razorpay-opencart, razorpay/razorpay-prestashop
or razorpay/razorpay-magento. A glob that only matches an invented example is a
glob that will tag nothing in production.
"""

from __future__ import annotations

import pytest
import yaml

from pramaan.policy.sensitive_paths import (
    DEFAULT_CONFIG_PATH,
    KNOWN_TAGS,
    PathRule,
    SensitivePathConfigError,
    default_rules,
    explain,
    load_rules,
    normalise_path,
    parse_rules,
    tag,
)
from pramaan.schemas import BusinessImpact


# --------------------------------------------------------------------------- #
# The shipped ruleset against real repository paths
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "path,expected",
    [
        # razorpay-woocommerce: the money path
        ("woo-razorpay.php", "payment_path"),
        ("includes/api/order.php", "payment_path"),
        ("includes/api/cart.php", "payment_path"),
        ("includes/api/coupon-apply.php", "payment_path"),
        ("includes/api/prepay-cod.php", "payment_path"),
        ("includes/api/shipping-info.php", "payment_path"),
        ("checkout-block.php", "payment_path"),
        ("includes/support/cartbounty.php", "payment_path"),
        ("includes/cron/one-click-checkout/one-cc-address-sync.php", "payment_path"),
        # razorpay-woocommerce: webhooks and Route settlements
        ("includes/razorpay-webhook.php", "kyc_or_settlement"),
        ("includes/razorpay-route.php", "kyc_or_settlement"),
        ("includes/razorpay-route-actions.php", "kyc_or_settlement"),
        # razorpay-php SDK, standalone and vendored
        ("src/Payment.php", "payment_path"),
        ("src/Settlement.php", "kyc_or_settlement"),
        ("src/Transfer.php", "kyc_or_settlement"),
        ("src/FundAccount.php", "kyc_or_settlement"),
        ("src/Account.php", "kyc_or_settlement"),
        ("src/Stakeholder.php", "kyc_or_settlement"),
        ("src/Document.php", "kyc_or_settlement"),
        ("src/Utility.php", "auth_or_session"),
        ("src/Webhook.php", "auth_or_session"),
        ("src/OAuthValidator.php", "auth_or_session"),
        ("src/Request.php", "auth_or_session"),
        ("src/Card.php", "pci_scope_hint"),
        ("src/Token.php", "pci_scope_hint"),
        ("src/Iin.php", "pci_scope_hint"),
        ("src/Errors/SignatureVerificationError.php", "auth_or_session"),
        ("razorpay-sdk/src/Payment.php", "payment_path"),
        ("razorpay-sdk/src/Utility.php", "auth_or_session"),
        ("razorpay-sdk/libs/Requests-2.0.4/src/Auth/Basic.php", "auth_or_session"),
        ("razorpay-sdk/libs/Requests-2.0.4/src/Cookie/Jar.php", "auth_or_session"),
        ("razorpay-sdk/libs/Requests-2.0.4/certificates/cacert.pem", "auth_or_session"),
        (".env.github", "auth_or_session"),
        # razorpay-opencart
        ("catalog/controller/payment/razorpay.php", "payment_path"),
        ("admin/model/payment/razorpay.php", "payment_path"),
        ("system/library/razorpay/razorpay-lib/createwebhook.php", "kyc_or_settlement"),
        ("system/library/razorpay/razorpay-sdk/src/Settlement.php", "kyc_or_settlement"),
        # razorpay-prestashop
        ("razorpay/controllers/front/validation.php", "payment_path"),
        ("razorpay/controllers/front/webhook.php", "kyc_or_settlement"),
        ("razorpay/controllers/front/order.php", "payment_path"),
        # razorpay-magento
        ("Controller/Payment/Callback.php", "payment_path"),
        ("Controller/Payment/Webhook.php", "kyc_or_settlement"),
        ("Model/PaymentMethod.php", "payment_path"),
        ("Model/Config.php", "auth_or_session"),
        ("Model/WebhookEvents.php", "kyc_or_settlement"),
        ("Plugin/CsrfValidatorSkip.php", "auth_or_session"),
        ("Model/Resolver/ResetCart.php", "payment_path"),
        # WooCommerce core, for host-repo scans
        ("includes/abstracts/abstract-wc-payment-gateway.php", "payment_path"),
        ("includes/class-wc-checkout.php", "payment_path"),
        ("includes/gateways/cod/class-wc-gateway-cod.php", "payment_path"),
    ],
)
def test_real_repository_paths_are_tagged(path, expected):
    assert getattr(tag(path), expected) is True, path


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "composer.json",
        "includes/state-map.php",
        "includes/debug.php",
        "public/js/bootstrap.min.js",
        "src/Collection.php",
        "src/Entity.php",
        "src/Resource.php",
        "src/ArrayableInterface.php",
        ".github/workflows/unit-tests.yml",
        "admin/view/template/payment/razorpay.twig",
        "Constants/OrderCronStatus.php",
    ],
)
def test_plainly_non_sensitive_paths_are_not_tagged(path):
    """The tagger has to discriminate. If everything is sensitive, the escalate
    rate is 100% and the harness has automated nothing."""
    assert tag(path).any_sensitive is False, path


def test_deeply_nested_vendored_copies_still_match():
    """The propagation case: one SDK defect fans out to every bundled copy, and
    each copy sits at a different depth."""
    for prefix in (
        "",
        "razorpay-sdk/",
        "system/library/razorpay/razorpay-sdk/",
        "razorpay/razorpay-sdk/",
        "wp-content/plugins/woo-razorpay/razorpay-sdk/",
    ):
        assert tag(f"{prefix}src/Settlement.php").kyc_or_settlement is True, prefix


def test_a_single_path_can_carry_several_tags():
    """Webhook handlers are simultaneously the money path, the auth boundary and
    a settlement trigger."""
    impact = tag("includes/razorpay-webhook.php")
    assert impact.payment_path is True
    assert impact.auth_or_session is True
    assert impact.kyc_or_settlement is True
    assert impact.pci_scope_hint is True


def test_tags_accumulate_across_matching_rules():
    """src/Card.php matches both the SDK money-resource rule and the card-data
    rule, and keeps the union of both."""
    impact = tag("src/Card.php")
    assert impact.pci_scope_hint is True
    assert impact.payment_path is True


def test_explain_names_the_rules_that_fired():
    """The report has to justify an escalation to the merchant, not just assert it."""
    rules = explain("includes/razorpay-webhook.php")
    assert "webhook-handlers" in {r.name for r in rules}
    assert all(r.intent for r in rules)


# --------------------------------------------------------------------------- #
# Path normalisation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw",
    [
        "includes/api/order.php",
        "./includes/api/order.php",
        "/includes/api/order.php",
        "includes//api/order.php",
        "includes\\api\\order.php",
        "  includes/api/order.php  ",
    ],
)
def test_scanner_path_spellings_normalise_to_the_same_tags(raw):
    """SARIF, Semgrep JSON and DefectDojo disagree about leading `./`, leading
    `/` and separator direction."""
    assert normalise_path(raw) == "includes/api/order.php"
    assert tag(raw).payment_path is True


def test_matching_is_case_insensitive():
    """Over-tagging costs a human review; under-tagging can auto-close a payment
    path. Only the second is a security failure, so casing errs generous."""
    assert tag("Includes/API/Order.php").payment_path is True
    assert tag("SRC/SETTLEMENT.PHP").kyc_or_settlement is True


def test_empty_path_raises_rather_than_reading_as_non_sensitive():
    """Ground rule 7. An all-false BusinessImpact for a missing path is
    auto-closeable, which makes an upstream bug a security failure."""
    for bad in ("", "   ", "/", "./", "//"):
        with pytest.raises(ValueError):
            tag(bad)


# --------------------------------------------------------------------------- #
# Glob semantics
# --------------------------------------------------------------------------- #

def _rules(*specs: tuple[str, list[str]]) -> tuple[PathRule, ...]:
    return tuple(
        PathRule.build(name=f"r{i}", tags=[t], globs=g, intent="test")
        for i, (t, g) in enumerate(specs)
    )


def test_single_star_does_not_cross_a_path_separator():
    """`includes/api/*.php` must not reach `includes/api/v2/order.php`; that is
    the whole reason this module does not use fnmatch."""
    rules = _rules(("payment_path", ["includes/api/*.php"]))
    assert tag("includes/api/order.php", rules).payment_path is True
    assert tag("includes/api/v2/order.php", rules).payment_path is False


def test_double_star_spans_zero_or_more_segments():
    rules = _rules(("payment_path", ["**/src/Payment.php"]))
    assert tag("src/Payment.php", rules).payment_path is True
    assert tag("a/src/Payment.php", rules).payment_path is True
    assert tag("a/b/c/d/src/Payment.php", rules).payment_path is True
    assert tag("src/sub/Payment.php", rules).payment_path is False


def test_globs_are_anchored_as_full_matches():
    """A substring match would let `notsrc/Payment.php.bak` tag as the SDK."""
    rules = _rules(("payment_path", ["src/Payment.php"]))
    assert tag("src/Payment.php", rules).payment_path is True
    assert tag("src/Payment.php.bak", rules).payment_path is False
    assert tag("xsrc/Payment.php", rules).payment_path is False


def test_question_mark_and_character_classes():
    rules = _rules(("auth_or_session", ["libs/Requests-?.[0-9].[0-9]/src/Auth.php"]))
    assert tag("libs/Requests-2.0.4/src/Auth.php", rules).auth_or_session is True
    assert tag("libs/Requests-1.8.0/src/Auth.php", rules).auth_or_session is True
    assert tag("libs/Requests-latest/src/Auth.php", rules).auth_or_session is False


def test_regex_metacharacters_in_a_glob_are_literal():
    """`.` in `*.php` must not match `Xphp`, or the tagger silently widens."""
    rules = _rules(("payment_path", ["src/Payment.php"]))
    assert tag("src/PaymentXphp", rules).payment_path is False


# --------------------------------------------------------------------------- #
# Config validation - fail loudly, never degrade to a ruleset that tags nothing
# --------------------------------------------------------------------------- #

def test_unknown_tag_name_is_a_load_error():
    """A typo'd tag silently matching nothing is exactly the D9 silent failure."""
    with pytest.raises(SensitivePathConfigError, match="unknown tag"):
        parse_rules({"rules": [{"name": "x", "tags": ["payment_paths"], "globs": ["*.php"]}]})


def test_rule_without_tags_or_globs_is_a_load_error():
    with pytest.raises(SensitivePathConfigError):
        parse_rules({"rules": [{"name": "x", "tags": [], "globs": ["*.php"]}]})
    with pytest.raises(SensitivePathConfigError):
        parse_rules({"rules": [{"name": "x", "tags": ["payment_path"], "globs": []}]})
    with pytest.raises(SensitivePathConfigError):
        parse_rules({"rules": [{"name": "", "tags": ["payment_path"], "globs": ["*.php"]}]})


def test_duplicate_rule_names_are_a_load_error():
    entry = {"name": "dup", "tags": ["payment_path"], "globs": ["*.php"]}
    with pytest.raises(SensitivePathConfigError, match="duplicate"):
        parse_rules({"rules": [entry, dict(entry)]})


def test_malformed_documents_are_load_errors():
    for bad in ([], {"rules": []}, {"rules": {}}, {}, "not a mapping"):
        with pytest.raises(SensitivePathConfigError):
            parse_rules(bad)


def test_missing_config_file_raises():
    with pytest.raises(SensitivePathConfigError, match="not found"):
        load_rules("/nonexistent/sensitive_paths.yaml")


# --------------------------------------------------------------------------- #
# The shipped config file itself
# --------------------------------------------------------------------------- #

def test_shipped_config_loads_and_every_rule_is_documented():
    rules = default_rules()
    assert len(rules) >= 10
    for rule in rules:
        assert rule.intent, f"{rule.name} has no stated intent"
        assert set(rule.tags) <= KNOWN_TAGS, rule.name
        assert rule.patterns


def test_shipped_config_covers_every_tag_in_the_schema():
    """If a tag has no rule, the model is its only source and D9's deterministic
    half does not exist for it."""
    covered = {t for rule in default_rules() for t in rule.tags}
    assert covered == KNOWN_TAGS


def test_known_tags_track_the_frozen_schema():
    assert KNOWN_TAGS == set(BusinessImpact.__dataclass_fields__)


def test_shipped_config_is_valid_yaml_with_quoted_globs():
    raw = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
    assert raw["version"] == 1
    for entry in raw["rules"]:
        for glob in entry["globs"]:
            assert isinstance(glob, str) and glob.strip() == glob


def test_default_rules_are_cached_and_shared():
    """Read once per process, not once per finding."""
    assert default_rules() is default_rules()
