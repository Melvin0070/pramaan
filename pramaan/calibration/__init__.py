"""Calibration — does a stated confidence mean anything, and where is the gate?

`tau.derive` answers the second question by repeated k-fold cross-validation
(D3) and returns a **spread**, never a point estimate. `reliability_diagram` and
`expected_calibration_error` answer the first.

All three are pure functions over the published verdict table, so the confidence
gate the policy engine acts on can be re-derived by a reader with no API key —
which is the only reason a published number about a model is worth anything.
"""

from pramaan.calibration.tau import (
    DEFAULT_SEED,
    NEVER_ACHIEVED,
    FoldTau,
    ReliabilityBin,
    ReliabilityDiagram,
    Spread,
    TauResult,
    derive,
    derive_per_corpus,
    expected_calibration_error,
    grouping_keys,
    kfold_indices,
    reliability_diagram,
)

__all__ = [
    "DEFAULT_SEED",
    "NEVER_ACHIEVED",
    "FoldTau",
    "ReliabilityBin",
    "ReliabilityDiagram",
    "Spread",
    "TauResult",
    "derive",
    "derive_per_corpus",
    "expected_calibration_error",
    "grouping_keys",
    "kfold_indices",
    "reliability_diagram",
]
