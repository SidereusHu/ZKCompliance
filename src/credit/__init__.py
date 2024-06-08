"""
ZK-Credit Module

Phase 5: 零知识信用评分

提供隐私保护的链上信用评分功能:
- 信用计算: 基于链上活动计算信用分
- 信用证明: 证明信用分达到某个阈值而不泄露具体分数
- 属性证明: 证明特定信用属性（如无逾期、交易活跃等）
- 信用验证: 验证信用证明的有效性
"""

from src.credit.score import (
    CreditScore,
    CreditFactor,
    CreditFactorType,
    ScoreRange,
    CreditScoreComputer,
)
from src.credit.proof import (
    CreditProof,
    CreditProver,
    AttributeProof,
    ThresholdProof,
)
from src.credit.verifier import (
    CreditVerifier,
    VerificationResult,
    CreditPolicy,
)

__all__ = [
    # Score
    "CreditScore",
    "CreditFactor",
    "CreditFactorType",
    "ScoreRange",
    "CreditScoreComputer",
    # Proof
    "CreditProof",
    "CreditProver",
    "AttributeProof",
    "ThresholdProof",
    # Verifier
    "CreditVerifier",
    "VerificationResult",
    "CreditPolicy",
]
