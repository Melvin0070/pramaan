"""Lane E — proof bundle assembly and the funnel (D4).

The gate itself lives in `pramaan.schemas.proof.ProofBundle.may_open_pr` and is
frozen. This package assembles bundles honestly and reports the stage-by-stage
survival curve that makes the AutoPatchBench gap visible instead of hiding it.
"""

from pramaan.proof.bundle import (
    STAGE_ORDER,
    FunnelReport,
    ProofRequest,
    build_bundle,
    funnel_report,
    run_proof,
    split_by_funnel,
)

__all__ = [
    "STAGE_ORDER",
    "FunnelReport",
    "ProofRequest",
    "build_bundle",
    "funnel_report",
    "run_proof",
    "split_by_funnel",
]
