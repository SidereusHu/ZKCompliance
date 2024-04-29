"""
ZK-AML Module

Phase 3: 零知识反洗钱

提供隐私保护的AML功能:
- 制裁筛查: 证明地址不在OFAC等制裁名单
- 来源证明: 证明资金来自合规渠道
- 关联集证明: Privacy Pools风格的合规证明
- 交易路径证明: 证明资金流转清白
"""

from src.aml.sanctions import (
    SanctionsList,
    SanctionsListType,
    SanctionsScreener,
    SanctionsProof,
    SanctionedEntity,
    AddressCommitment,
    OFAC_SDN_LIST,
    EU_SANCTIONS_LIST,
    UN_SANCTIONS_LIST,
    create_default_screener,
)
from src.aml.source_proof import (
    TransactionSource,
    SourceProof,
    SourceProver,
    SourceVerifier,
    SourceType,
    COMPLIANT_SOURCES,
)
from src.aml.privacy_pools import (
    AssociationSet,
    AssociationProof,
    PrivacyPoolProver,
    PrivacyPoolVerifier,
    DepositRecord,
    WithdrawalRecord,
)
from src.aml.verifier import (
    AMLVerifier,
    AMLPolicy,
    AMLRequirement,
    AMLVerificationResult,
    AMLRequirementType,
    BASIC_AML_POLICY,
    STRICT_AML_POLICY,
    DEFI_AML_POLICY,
)

__all__ = [
    # Sanctions
    "SanctionsList",
    "SanctionsListType",
    "SanctionsScreener",
    "SanctionsProof",
    "SanctionedEntity",
    "AddressCommitment",
    "OFAC_SDN_LIST",
    "EU_SANCTIONS_LIST",
    "UN_SANCTIONS_LIST",
    "create_default_screener",
    # Source Proof
    "TransactionSource",
    "SourceProof",
    "SourceProver",
    "SourceVerifier",
    "SourceType",
    "COMPLIANT_SOURCES",
    # Privacy Pools
    "AssociationSet",
    "AssociationProof",
    "PrivacyPoolProver",
    "PrivacyPoolVerifier",
    "DepositRecord",
    "WithdrawalRecord",
    # Verifier
    "AMLVerifier",
    "AMLPolicy",
    "AMLRequirement",
    "AMLVerificationResult",
    "AMLRequirementType",
    "BASIC_AML_POLICY",
    "STRICT_AML_POLICY",
    "DEFI_AML_POLICY",
]
