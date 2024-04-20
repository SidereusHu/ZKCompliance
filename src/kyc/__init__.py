"""
ZK-KYC Module

Phase 2: 零知识身份验证

提供隐私保护的KYC功能:
- 年龄证明 (不泄露出生日期)
- 国籍证明 (不泄露具体国家)
- 属性证明 (通用可验证凭证)
- 凭证签发与验证
"""

from src.kyc.credential import (
    Credential,
    CredentialSchema,
    CredentialAttribute,
    AttributeType,
    CredentialStatus,
    SignedCredential,
    IDENTITY_SCHEMA,
    AGE_SCHEMA,
    NATIONALITY_SCHEMA,
    ADDRESS_SCHEMA,
    create_credential,
    compute_age,
    date_to_days_since_epoch,
)
from src.kyc.age_proof import (
    AgeProver,
    AgeVerifier,
    AgeProof,
    AgeCredential,
    create_test_age_credential,
)
from src.kyc.membership_proof import (
    MembershipProver,
    MembershipVerifier,
    MembershipProof,
    SetCommitment,
    FATF_HIGH_RISK_COUNTRIES,
    FATF_GREY_LIST_COUNTRIES,
    COMPLIANT_COUNTRIES,
    OFAC_SANCTIONED_COUNTRIES,
    create_nationality_whitelist,
    create_nationality_blacklist,
)
from src.kyc.issuer import (
    CredentialIssuer,
    IssuerKeyPair,
    IssuanceRequest,
    IssuanceResponse,
    BlindCredentialHolder,
)
from src.kyc.verifier import (
    KYCVerifier,
    VerificationRequest,
    VerificationResult,
    VerificationPolicy,
    VerificationRequirement,
    RequirementType,
    VerificationStatus,
    RequirementResult,
    BASIC_KYC_POLICY,
    FINANCIAL_KYC_POLICY,
    HIGH_VALUE_KYC_POLICY,
    AGE_RESTRICTED_POLICY,
)

__all__ = [
    # Credential
    "Credential",
    "CredentialSchema",
    "CredentialAttribute",
    "AttributeType",
    "CredentialStatus",
    "SignedCredential",
    "IDENTITY_SCHEMA",
    "AGE_SCHEMA",
    "NATIONALITY_SCHEMA",
    "ADDRESS_SCHEMA",
    "create_credential",
    "compute_age",
    "date_to_days_since_epoch",
    # Age Proof
    "AgeProver",
    "AgeVerifier",
    "AgeProof",
    "AgeCredential",
    "create_test_age_credential",
    # Membership Proof
    "MembershipProver",
    "MembershipVerifier",
    "MembershipProof",
    "SetCommitment",
    "FATF_HIGH_RISK_COUNTRIES",
    "FATF_GREY_LIST_COUNTRIES",
    "COMPLIANT_COUNTRIES",
    "OFAC_SANCTIONED_COUNTRIES",
    "create_nationality_whitelist",
    "create_nationality_blacklist",
    # Issuer
    "CredentialIssuer",
    "IssuerKeyPair",
    "IssuanceRequest",
    "IssuanceResponse",
    "BlindCredentialHolder",
    # Verifier
    "KYCVerifier",
    "VerificationRequest",
    "VerificationResult",
    "VerificationPolicy",
    "VerificationRequirement",
    "RequirementType",
    "VerificationStatus",
    "RequirementResult",
    "BASIC_KYC_POLICY",
    "FINANCIAL_KYC_POLICY",
    "HIGH_VALUE_KYC_POLICY",
    "AGE_RESTRICTED_POLICY",
]
