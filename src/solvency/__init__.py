"""
ZK-Solvency Module

Phase 4: 零知识储备金证明

提供交易所/托管机构的储备金证明功能:
- 负债承诺: Merkle Sum Tree承诺所有用户余额
- 资产证明: 证明持有足够资产覆盖负债
- 用户验证: 允许用户验证自己的余额被正确包含
- 隐私保护: 不泄露任何个人余额或总资产信息
"""

from src.solvency.merkle_sum_tree import (
    MerkleSumTree,
    MerkleSumNode,
    UserBalance,
    InclusionProof,
)
from src.solvency.asset_commitment import (
    Asset,
    AssetCommitment,
    AssetProof,
    AssetProver,
    AssetVerifier,
)
from src.solvency.proof_of_reserves import (
    ProofOfReserves,
    ReservesProver,
    ReservesVerifier,
    SolvencyStatus,
    AuditReport,
)
from src.solvency.individual_verification import (
    UserProof,
    UserVerifier,
    VerificationResult,
)

__all__ = [
    # Merkle Sum Tree
    "MerkleSumTree",
    "MerkleSumNode",
    "UserBalance",
    "InclusionProof",
    # Asset Commitment
    "Asset",
    "AssetCommitment",
    "AssetProof",
    "AssetProver",
    "AssetVerifier",
    # Proof of Reserves
    "ProofOfReserves",
    "ReservesProver",
    "ReservesVerifier",
    "SolvencyStatus",
    "AuditReport",
    # Individual Verification
    "UserProof",
    "UserVerifier",
    "VerificationResult",
]
