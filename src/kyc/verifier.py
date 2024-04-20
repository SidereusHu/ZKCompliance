"""
KYC验证器

实现统一的KYC验证接口:
- 验证各种零知识证明
- 支持多种验证策略
- 批量验证
- 验证结果管理
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, date
from typing import Optional, List, Dict, Any, Set, Union
from enum import Enum
import hashlib
import json

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    BN128,
)
from src.kyc.credential import (
    Credential,
    SignedCredential,
    CredentialStatus,
)
from src.kyc.age_proof import AgeProof, AgeVerifier
from src.kyc.membership_proof import (
    MembershipProof,
    MembershipVerifier,
    SetCommitment,
)


class VerificationStatus(Enum):
    """验证状态"""
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class RequirementType(Enum):
    """要求类型"""
    AGE_GTE = "age_gte"           # 年龄 >= threshold
    AGE_LTE = "age_lte"           # 年龄 <= threshold
    AGE_RANGE = "age_range"       # 年龄在范围内
    NATIONALITY_IN = "nationality_in"       # 国籍在白名单
    NATIONALITY_NOT_IN = "nationality_not_in"  # 国籍不在黑名单
    ATTRIBUTE_EQUALS = "attribute_equals"   # 属性等于某值
    CUSTOM = "custom"             # 自定义验证


@dataclass
class VerificationRequirement:
    """验证要求"""
    requirement_type: RequirementType
    parameters: Dict[str, Any]
    required: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.requirement_type.value,
            "parameters": self.parameters,
            "required": self.required,
            "description": self.description,
        }


@dataclass
class VerificationPolicy:
    """验证策略

    定义一组验证要求。
    """
    policy_id: str
    name: str
    requirements: List[VerificationRequirement]
    description: str = ""
    created_at: dt = dc_field(default_factory=dt.now)
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "requirements": [r.to_dict() for r in self.requirements],
            "description": self.description,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class VerificationRequest:
    """验证请求

    提交给验证者的验证请求。
    """
    request_id: str
    policy_id: str
    proofs: Dict[str, Any]  # 证明数据
    submitted_at: dt = dc_field(default_factory=dt.now)
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "policy_id": self.policy_id,
            "submitted_at": self.submitted_at.isoformat(),
        }


@dataclass
class RequirementResult:
    """单个要求的验证结果"""
    requirement_type: RequirementType
    passed: bool
    details: Dict[str, Any] = dc_field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass
class VerificationResult:
    """验证结果

    验证请求的完整结果。
    """
    request_id: str
    status: VerificationStatus
    policy_id: str
    requirement_results: List[RequirementResult]
    verified_at: dt = dc_field(default_factory=dt.now)
    expires_at: Optional[dt] = None
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    @property
    def all_passed(self) -> bool:
        """所有要求是否都通过"""
        return all(r.passed for r in self.requirement_results)

    @property
    def required_passed(self) -> bool:
        """所有必需要求是否都通过"""
        # 这里简化处理，假设所有结果都是必需的
        return all(r.passed for r in self.requirement_results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status.value,
            "policy_id": self.policy_id,
            "all_passed": self.all_passed,
            "requirement_results": [
                {
                    "type": r.requirement_type.value,
                    "passed": r.passed,
                    "details": r.details,
                    "error": r.error_message,
                }
                for r in self.requirement_results
            ],
            "verified_at": self.verified_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class KYCVerifier:
    """KYC验证器

    统一的KYC证明验证接口。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

        # 子验证器
        self.age_verifier = AgeVerifier(self.curve)
        self.membership_verifier = MembershipVerifier(self.curve)

        # 验证策略
        self.policies: Dict[str, VerificationPolicy] = {}

        # 已知的集合承诺（国籍白名单/黑名单等）
        self.set_commitments: Dict[str, SetCommitment] = {}

        # 发行者公钥
        self.issuer_public_keys: Dict[str, Point] = {}

        # 验证历史
        self.verification_history: Dict[str, VerificationResult] = {}

    def register_policy(self, policy: VerificationPolicy) -> None:
        """注册验证策略"""
        self.policies[policy.policy_id] = policy

    def register_set_commitment(
        self,
        set_id: str,
        commitment: SetCommitment
    ) -> None:
        """注册集合承诺"""
        self.set_commitments[set_id] = commitment

    def register_issuer(self, issuer_id: str, public_key: Point) -> None:
        """注册发行者公钥"""
        self.issuer_public_keys[issuer_id] = public_key

    def verify(self, request: VerificationRequest) -> VerificationResult:
        """执行验证

        Args:
            request: 验证请求

        Returns:
            VerificationResult
        """
        # 查找策略
        if request.policy_id not in self.policies:
            return VerificationResult(
                request_id=request.request_id,
                status=VerificationStatus.FAILED,
                policy_id=request.policy_id,
                requirement_results=[
                    RequirementResult(
                        requirement_type=RequirementType.CUSTOM,
                        passed=False,
                        error_message=f"Unknown policy: {request.policy_id}",
                    )
                ],
            )

        policy = self.policies[request.policy_id]
        requirement_results = []

        # 验证每个要求
        for requirement in policy.requirements:
            result = self._verify_requirement(requirement, request.proofs)
            requirement_results.append(result)

        # 确定最终状态
        if all(r.passed for r in requirement_results):
            status = VerificationStatus.VERIFIED
        else:
            status = VerificationStatus.FAILED

        result = VerificationResult(
            request_id=request.request_id,
            status=status,
            policy_id=request.policy_id,
            requirement_results=requirement_results,
        )

        # 记录历史
        self.verification_history[request.request_id] = result

        return result

    def _verify_requirement(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证单个要求"""
        try:
            if requirement.requirement_type == RequirementType.AGE_GTE:
                return self._verify_age_gte(requirement, proofs)
            elif requirement.requirement_type == RequirementType.AGE_LTE:
                return self._verify_age_lte(requirement, proofs)
            elif requirement.requirement_type == RequirementType.AGE_RANGE:
                return self._verify_age_range(requirement, proofs)
            elif requirement.requirement_type == RequirementType.NATIONALITY_IN:
                return self._verify_nationality_in(requirement, proofs)
            elif requirement.requirement_type == RequirementType.NATIONALITY_NOT_IN:
                return self._verify_nationality_not_in(requirement, proofs)
            elif requirement.requirement_type == RequirementType.ATTRIBUTE_EQUALS:
                return self._verify_attribute_equals(requirement, proofs)
            else:
                return RequirementResult(
                    requirement_type=requirement.requirement_type,
                    passed=False,
                    error_message=f"Unsupported requirement type: {requirement.requirement_type}",
                )
        except Exception as e:
            return RequirementResult(
                requirement_type=requirement.requirement_type,
                passed=False,
                error_message=str(e),
            )

    def _verify_age_gte(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证年龄 >= threshold"""
        threshold = requirement.parameters.get("threshold", 18)

        # 获取年龄证明
        age_proof_data = proofs.get("age_proof")
        if not age_proof_data:
            return RequirementResult(
                requirement_type=RequirementType.AGE_GTE,
                passed=False,
                error_message="Age proof not provided",
            )

        # 如果是AgeProof对象
        if isinstance(age_proof_data, AgeProof):
            passed = self.age_verifier.verify_age_gte(
                age_proof_data,
                threshold,
            )
        else:
            # 简化: 假设传入的是预验证标记
            passed = age_proof_data.get("verified", False)

        return RequirementResult(
            requirement_type=RequirementType.AGE_GTE,
            passed=passed,
            details={"threshold": threshold},
        )

    def _verify_age_lte(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证年龄 <= threshold"""
        threshold = requirement.parameters.get("threshold", 65)

        age_proof_data = proofs.get("age_proof")
        if not age_proof_data:
            return RequirementResult(
                requirement_type=RequirementType.AGE_LTE,
                passed=False,
                error_message="Age proof not provided",
            )

        # 简化验证
        if isinstance(age_proof_data, AgeProof):
            # 需要额外的范围证明逻辑
            passed = age_proof_data.claim_type == "lte"
        else:
            passed = age_proof_data.get("verified", False)

        return RequirementResult(
            requirement_type=RequirementType.AGE_LTE,
            passed=passed,
            details={"threshold": threshold},
        )

    def _verify_age_range(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证年龄在范围内"""
        min_age = requirement.parameters.get("min_age", 18)
        max_age = requirement.parameters.get("max_age", 65)

        age_proof_data = proofs.get("age_proof")
        if not age_proof_data:
            return RequirementResult(
                requirement_type=RequirementType.AGE_RANGE,
                passed=False,
                error_message="Age proof not provided",
            )

        if isinstance(age_proof_data, AgeProof):
            passed = self.age_verifier.verify_age_in_range(
                age_proof_data,
                min_age,
                max_age,
            )
        else:
            passed = age_proof_data.get("verified", False)

        return RequirementResult(
            requirement_type=RequirementType.AGE_RANGE,
            passed=passed,
            details={"min_age": min_age, "max_age": max_age},
        )

    def _verify_nationality_in(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证国籍在白名单中"""
        set_id = requirement.parameters.get("set_id")
        allowed_countries = requirement.parameters.get("countries", [])

        membership_proof = proofs.get("membership_proof")
        if not membership_proof:
            return RequirementResult(
                requirement_type=RequirementType.NATIONALITY_IN,
                passed=False,
                error_message="Membership proof not provided",
            )

        # 获取期望的集合承诺
        expected_root = None
        if set_id and set_id in self.set_commitments:
            expected_root = self.set_commitments[set_id].root

        if isinstance(membership_proof, MembershipProof):
            passed = self.membership_verifier.verify_membership(
                membership_proof,
                expected_root,
            )
        else:
            passed = membership_proof.get("verified", False)

        return RequirementResult(
            requirement_type=RequirementType.NATIONALITY_IN,
            passed=passed,
            details={"set_id": set_id},
        )

    def _verify_nationality_not_in(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证国籍不在黑名单中"""
        set_id = requirement.parameters.get("set_id")
        excluded_countries = requirement.parameters.get("countries", [])

        membership_proof = proofs.get("non_membership_proof")
        if not membership_proof:
            return RequirementResult(
                requirement_type=RequirementType.NATIONALITY_NOT_IN,
                passed=False,
                error_message="Non-membership proof not provided",
            )

        if isinstance(membership_proof, MembershipProof):
            passed = self.membership_verifier.verify_non_membership(
                membership_proof,
            )
        else:
            passed = membership_proof.get("verified", False)

        return RequirementResult(
            requirement_type=RequirementType.NATIONALITY_NOT_IN,
            passed=passed,
            details={"set_id": set_id},
        )

    def _verify_attribute_equals(
        self,
        requirement: VerificationRequirement,
        proofs: Dict[str, Any],
    ) -> RequirementResult:
        """验证属性等于某值"""
        attribute_name = requirement.parameters.get("attribute")
        expected_value = requirement.parameters.get("value")

        # 简化实现
        attribute_proof = proofs.get(f"attribute_{attribute_name}")
        if not attribute_proof:
            return RequirementResult(
                requirement_type=RequirementType.ATTRIBUTE_EQUALS,
                passed=False,
                error_message=f"Attribute proof for '{attribute_name}' not provided",
            )

        passed = attribute_proof.get("verified", False)

        return RequirementResult(
            requirement_type=RequirementType.ATTRIBUTE_EQUALS,
            passed=passed,
            details={"attribute": attribute_name},
        )

    def batch_verify(
        self,
        requests: List[VerificationRequest]
    ) -> List[VerificationResult]:
        """批量验证"""
        return [self.verify(req) for req in requests]

    def get_verification_result(
        self,
        request_id: str
    ) -> Optional[VerificationResult]:
        """获取验证结果"""
        return self.verification_history.get(request_id)


# ============================================================
# 预定义验证策略
# ============================================================

# 基本KYC策略（年龄 >= 18）
BASIC_KYC_POLICY = VerificationPolicy(
    policy_id="basic-kyc",
    name="Basic KYC",
    description="Basic KYC verification requiring age >= 18",
    requirements=[
        VerificationRequirement(
            requirement_type=RequirementType.AGE_GTE,
            parameters={"threshold": 18},
            description="User must be at least 18 years old",
        ),
    ],
)

# 金融服务KYC策略
FINANCIAL_KYC_POLICY = VerificationPolicy(
    policy_id="financial-kyc",
    name="Financial Services KYC",
    description="KYC for financial services with age and nationality requirements",
    requirements=[
        VerificationRequirement(
            requirement_type=RequirementType.AGE_GTE,
            parameters={"threshold": 18},
            description="User must be at least 18 years old",
        ),
        VerificationRequirement(
            requirement_type=RequirementType.NATIONALITY_NOT_IN,
            parameters={
                "set_id": "ofac-sanctions",
                "countries": ["KP", "IR", "CU", "SY"],
            },
            description="User must not be from OFAC sanctioned countries",
        ),
    ],
)

# 高风险交易策略
HIGH_VALUE_KYC_POLICY = VerificationPolicy(
    policy_id="high-value-kyc",
    name="High Value Transaction KYC",
    description="Enhanced KYC for high-value transactions",
    requirements=[
        VerificationRequirement(
            requirement_type=RequirementType.AGE_GTE,
            parameters={"threshold": 21},
            description="User must be at least 21 years old",
        ),
        VerificationRequirement(
            requirement_type=RequirementType.NATIONALITY_IN,
            parameters={
                "set_id": "compliant-countries",
                "countries": ["US", "GB", "DE", "FR", "JP", "CA", "AU", "SG"],
            },
            description="User must be from a compliant jurisdiction",
        ),
        VerificationRequirement(
            requirement_type=RequirementType.NATIONALITY_NOT_IN,
            parameters={
                "set_id": "fatf-high-risk",
                "countries": ["KP", "IR", "MM"],
            },
            description="User must not be from FATF high-risk countries",
        ),
    ],
)

# 年龄限制内容策略
AGE_RESTRICTED_POLICY = VerificationPolicy(
    policy_id="age-restricted",
    name="Age Restricted Content",
    description="Verification for age-restricted content",
    requirements=[
        VerificationRequirement(
            requirement_type=RequirementType.AGE_GTE,
            parameters={"threshold": 21},
            description="User must be at least 21 years old",
        ),
    ],
)
