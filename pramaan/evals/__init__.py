"""Lane F — the Kasauti eval suite (कसौटी, touchstone).

The measurement layer. Everything here is a pure function over cached `Attempt`
rows and a human label sheet: no network, no clock, no model, no API key. That
is a design constraint rather than a convenience, because the project's claim is
the *published measurement*, and a measurement nobody else can re-run is a press
release. Given `verdict_table.jsonl` and a label sheet, every number in the trust
report re-derives on a laptop with the network off.

Three habits run through the whole lane:

  * **No bare rate.** `stats.Rate` carries its counts and a Wilson interval, and
    refuses to hand over a point estimate below its reporting minimum.
  * **No blended corpora.** D16 is enforced in code by `labels.one_corpus`, not
    documented in prose.
  * **No number without its denominator's story.** Per-channel injection ASR,
    fold spread instead of a point tau, the schema-failure rate beside pass^k.
"""

from pramaan.evals.agreement import (
    IntraRaterAgreement,
    ModelHumanAgreement,
    Rating,
    WashoutViolation,
    intra_rater_kappa,
    model_vs_human_agreement,
)
from pramaan.evals.audit_sample import (
    AuditOutcome,
    AuditResult,
    AuditSample,
    draw,
    eligible_ids,
    record,
)
from pramaan.evals.consistency import (
    ConsistencyResult,
    GroupOutcome,
    InconsistentGroup,
    pass_at_k,
    pass_at_k_by_corpus,
    schema_failure_rate,
)
from pramaan.evals.injection import (
    CONTROL_ARM,
    HARDENED_ARM,
    ArmConfig,
    ArmResult,
    ChannelResult,
    PairedInjectionResult,
    PositiveControlError,
    TrialObservation,
    TrialResult,
    run_paired,
    score_trial,
)
from pramaan.evals.labels import (
    GroundTruth,
    LabelledVerdict,
    canonical_order,
    check_scoring_unit,
    from_attempts,
    one_corpus,
    one_row_per_finding,
    repeated_findings,
    split_by_corpus,
)
from pramaan.evals.metrics import (
    MISS_WEIGHT,
    Confusion,
    CostModel,
    MetricsResult,
    confusion,
    fp_class_metrics,
    fp_class_metrics_per_corpus,
)
from pramaan.evals.payloads import CANARY, CHANNELS, PAYLOADS, Channel, Payload
from pramaan.evals.runner import (
    CorpusReport,
    EpochLeakError,
    GateResult,
    StaleEpochError,
    SuiteResult,
    ci_suite,
    evaluate_gates,
    nightly_suite,
    stratified_subset,
)
from pramaan.evals.stats import (
    BlendedCorpusError,
    EvalError,
    InsufficientData,
    Rate,
    RepeatedRunsError,
    wilson_interval,
    zero_events_upper_bound,
)

__all__ = [
    "IntraRaterAgreement", "ModelHumanAgreement", "Rating", "WashoutViolation",
    "intra_rater_kappa", "model_vs_human_agreement",
    "AuditOutcome", "AuditResult", "AuditSample", "draw", "eligible_ids", "record",
    "ConsistencyResult", "GroupOutcome", "InconsistentGroup", "pass_at_k",
    "pass_at_k_by_corpus", "schema_failure_rate",
    "CONTROL_ARM", "HARDENED_ARM", "ArmConfig", "ArmResult", "ChannelResult",
    "PairedInjectionResult", "PositiveControlError", "TrialObservation",
    "TrialResult", "run_paired", "score_trial",
    "GroundTruth", "LabelledVerdict", "canonical_order", "check_scoring_unit",
    "from_attempts", "one_corpus", "one_row_per_finding", "repeated_findings",
    "split_by_corpus",
    "MISS_WEIGHT", "Confusion", "CostModel", "MetricsResult", "confusion",
    "fp_class_metrics", "fp_class_metrics_per_corpus",
    "CANARY", "CHANNELS", "PAYLOADS", "Channel", "Payload",
    "CorpusReport", "EpochLeakError", "GateResult", "StaleEpochError",
    "SuiteResult", "ci_suite", "evaluate_gates", "nightly_suite",
    "stratified_subset",
    "BlendedCorpusError", "EvalError", "InsufficientData", "Rate",
    "RepeatedRunsError", "wilson_interval", "zero_events_upper_bound",
]
