"""
AML Verifier - 反洗钱验证器

整合所有AML组件，提供统一的合规验证接口:
- 制裁筛查
- 来源证明
- Privacy Pools关联证明

支持可配置的合规策略，适用于不同的监管环境和风险偏好。
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Set, Tuple, Any
from datetime import datetime
import hashlib
import secrets

from src.aml.sanctions import (
    SanctionsScreener,
    SanctionsProof,
    SanctionsList,
    SanctionsListType,
    OFAC_SDN_LIST,
    EU_SANCTIONS_LIST,
    UN_SANCTIONS_LIST,
)
from src.aml.source_proof import (
    SourceProver,
    SourceVerifier,
    SourceProof,
    SourceType,
    RiskLevel,
    COMPLIANT_SOURCES,
)
from src.aml.privacy_pools import (
    PrivacyPool,
    PrivacyPoolProver,
    PrivacyPoolVerifier,
    AssociationSet,
    AssociationSetType,
    AssociationProof,
    WithdrawalRecord,
)


class AMLRequirementType(Enum):
    """AML要求类型"""
    SANCTIONS_CHECK = auto()  # 制裁名单检查
    SOURCE_VERIFICATION = auto()  # 来源验证
    ASSOCIATION_PROOF = auto()  # 关联集证明
    RISK_THRESHOLD = auto()  # 风险阈值
    VOLUME_LIMIT = auto()  # 交易量限制
    VELOCITY_CHECK = auto()  # 交易频率检查
    GEOGRAPHIC_RESTRICTION = auto()  # 地理限制
    TIME_RESTRICTION = auto()  # 时间限制


@dataclass
class AMLRequirement:
    """AML合规要求"""
    requirement_type: AMLRequirementType
    name: str
    description: str
    is_mandatory: bool = True

    # 具体参数
    params: Dict[str, Any] = field(default_factory=dict)

    # 失败时的处理
    on_failure: str = "reject"  # reject, warn, log

    def __hash__(self):
        return hash((self.requirement_type, self.name))


@dataclass
class AMLPolicy:
    """
    AML合规策略

    定义一组必须满足的合规要求。
    不同的策略适用于不同的:
    - 监管环境 (US, EU, APAC等)
    - 交易类型 (个人, 机构)
    - 风险偏好 (保守, 标准, 激进)
    """
    policy_id: str
    name: str
    description: str

    # 要求列表
    requirements: List[AMLRequirement] = field(default_factory=list)

    # 制裁名单
    sanctions_lists: List[SanctionsListType] = field(default_factory=list)

    # 允许的来源类型
    allowed_source_types: Set[SourceType] = field(default_factory=set)

    # 允许的关联集类型
    allowed_association_types: Set[AssociationSetType] = field(default_factory=set)

    # 风险阈值
    max_risk_level: RiskLevel = RiskLevel.MEDIUM

    # 交易限制
    max_single_transaction: int = 0  # 0表示无限制
    max_daily_volume: int = 0
    max_monthly_volume: int = 0

    # 元数据
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    jurisdiction: str = "global"

    def add_requirement(self, requirement: AMLRequirement) -> None:
        """添加要求"""
        self.requirements.append(requirement)

    def get_mandatory_requirements(self) -> List[AMLRequirement]:
        """获取强制性要求"""
        return [r for r in self.requirements if r.is_mandatory]


@dataclass
class AMLVerificationResult:
    """AML验证结果"""
    verification_id: str
    policy_id: str
    timestamp: datetime

    # 总体结果
    is_compliant: bool
    overall_risk_level: RiskLevel

    # 各项检查结果
    sanctions_check_passed: bool = False
    source_verified: bool = False
    association_proved: bool = False

    # 详细结果
    requirement_results: Dict[str, Tuple[bool, str]] = field(default_factory=dict)

    # 证明
    sanctions_proof: Optional[SanctionsProof] = None
    source_proof: Optional[SourceProof] = None
    association_proof: Optional[AssociationProof] = None

    # 错误和警告
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)


class AMLVerifier:
    """
    AML验证器

    提供完整的反洗钱合规验证流程:
    1. 制裁名单筛查
    2. 资金来源验证
    3. 关联集证明验证
    4. 风险评估
    """

    def __init__(self, policy: Optional[AMLPolicy] = None):
        self.policy = policy or self._default_policy()

        # 初始化各组件
        self.sanctions_screener = SanctionsScreener()
        self.source_prover = SourceProver()
        self.source_verifier = SourceVerifier()
        self.pool_prover = PrivacyPoolProver()
        self.pool_verifier = PrivacyPoolVerifier()

        # 注册制裁名单
        self._register_sanctions_lists()

        # 验证历史
        self.verification_history: List[AMLVerificationResult] = []

    # 风险等级数值映射
    RISK_VALUES = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4
    }

    def _risk_value(self, level: RiskLevel) -> int:
        """获取风险等级的数值"""
        return self.RISK_VALUES.get(level, 2)

    def _default_policy(self) -> AMLPolicy:
        """创建默认策略"""
        return BASIC_AML_POLICY

    def _register_sanctions_lists(self) -> None:
        """注册策略要求的制裁名单"""
        list_map = {
            SanctionsListType.OFAC_SDN: OFAC_SDN_LIST,
            SanctionsListType.EU_SANCTIONS: EU_SANCTIONS_LIST,
            SanctionsListType.UN_SANCTIONS: UN_SANCTIONS_LIST,
        }

        for list_type in self.policy.sanctions_lists:
            if list_type in list_map:
                self.sanctions_screener.register_sanctions_list(
                    list_type,
                    list_map[list_type]
                )

    def set_policy(self, policy: AMLPolicy) -> None:
        """设置新策略"""
        self.policy = policy
        self._register_sanctions_lists()

    def verify_address(
        self,
        address: str,
        address_secret: bytes,
        source_tx_hash: Optional[str] = None,
        source_chain: Optional[str] = None,
        pool: Optional[PrivacyPool] = None,
        association_set_id: Optional[str] = None
    ) -> AMLVerificationResult:
        """
        完整的AML验证流程

        Args:
            address: 要验证的地址
            address_secret: 地址秘密(用于生成承诺)
            source_tx_hash: 资金来源交易哈希
            source_chain: 来源链
            pool: 隐私池(如果使用Privacy Pools)
            association_set_id: 关联集ID

        Returns:
            AMLVerificationResult
        """
        result = AMLVerificationResult(
            verification_id=secrets.token_hex(16),
            policy_id=self.policy.policy_id,
            timestamp=datetime.now(),
            is_compliant=True,
            overall_risk_level=RiskLevel.LOW
        )

        # 1. 制裁名单检查
        sanctions_result = self._check_sanctions(address, address_secret, result)
        if not sanctions_result:
            result.is_compliant = False

        # 2. 来源验证(如果提供了来源信息)
        if source_tx_hash:
            source_result = self._verify_source(
                address, source_tx_hash, source_chain, result
            )
            if not source_result:
                # 来源验证失败可能只是警告
                if self._is_source_mandatory():
                    result.is_compliant = False

        # 3. 关联证明验证(如果使用Privacy Pools)
        if pool and association_set_id:
            assoc_result = self._verify_association(
                pool, association_set_id, address, address_secret, result
            )
            if not assoc_result:
                if self._is_association_mandatory():
                    result.is_compliant = False

        # 4. 检查所有强制性要求
        self._check_all_requirements(address, result)

        # 5. 计算总体风险等级
        result.overall_risk_level = self._calculate_overall_risk(result)

        # 6. 最终合规判定
        if self._risk_value(result.overall_risk_level) > self._risk_value(self.policy.max_risk_level):
            result.is_compliant = False
            result.errors.append(
                f"Risk level {result.overall_risk_level.name} exceeds maximum "
                f"allowed {self.policy.max_risk_level.name}"
            )

        # 保存历史
        self.verification_history.append(result)

        return result

    def _check_sanctions(
        self,
        address: str,
        secret: bytes,
        result: AMLVerificationResult
    ) -> bool:
        """执行制裁名单检查"""
        try:
            # 创建地址承诺(使用secret的哈希作为盲因子)
            import hashlib
            blinding = int.from_bytes(
                hashlib.sha256(secret).digest(),
                'big'
            ) % (self.sanctions_screener.curve.n - 1) + 1

            commitment = self.sanctions_screener.create_address_commitment(
                address,
                blinding_factor=blinding
            )

            # 生成非制裁证明
            proof = self.sanctions_screener.prove_not_sanctioned(address, commitment)

            if proof and proof.is_valid():
                result.sanctions_check_passed = True
                result.sanctions_proof = proof
                result.requirement_results["sanctions_check"] = (True, "Address not sanctioned")
                return True
            else:
                result.sanctions_check_passed = False
                result.errors.append("Failed to prove address is not sanctioned")
                result.requirement_results["sanctions_check"] = (False, "Sanctions proof failed")
                return False

        except Exception as e:
            result.errors.append(f"Sanctions check error: {str(e)}")
            result.requirement_results["sanctions_check"] = (False, str(e))
            return False

    def _verify_source(
        self,
        address: str,
        tx_hash: str,
        chain: Optional[str],
        result: AMLVerificationResult
    ) -> bool:
        """验证资金来源"""
        from datetime import datetime as dt
        from src.aml.source_proof import TransactionSource

        try:
            # 创建模拟交易记录(实际应从链上获取)
            mock_tx = TransactionSource(
                tx_hash=tx_hash,
                source_type=SourceType.CEX_WITHDRAWAL,
                from_address="0xExchange",
                to_address=address,
                amount=int(1 * 10**18),
                block_number=18000000,
                timestamp=dt.now(),
                platform="exchange",
                risk_level=RiskLevel.LOW,
                verified=True
            )

            # 分析来源链
            source_chain = self.source_prover.analyze_source_chain(
                address,
                [mock_tx],
                max_depth=5
            )

            # 检查来源类型是否允许
            source_types_found = {tx.source_type for tx in source_chain.transactions}
            allowed = self.policy.allowed_source_types

            if allowed:
                disallowed = source_types_found - allowed
                if disallowed:
                    result.warnings.append(
                        f"Found disallowed source types: {[t.value for t in disallowed]}"
                    )

            # 生成来源证明
            proof = self.source_prover.prove_compliant_source(
                address,
                source_chain
            )

            if proof:
                result.source_verified = True
                result.source_proof = proof
                risk_name = proof.disclosed_risk_level.name if proof.disclosed_risk_level else "UNKNOWN"
                result.requirement_results["source_verification"] = (
                    True,
                    f"Source verified: {risk_name} risk"
                )

                # 更新风险等级
                if proof.disclosed_risk_level:
                    if self._risk_value(proof.disclosed_risk_level) > self._risk_value(result.overall_risk_level):
                        result.overall_risk_level = proof.disclosed_risk_level

                return True
            else:
                result.source_verified = False
                msg = "Source verification failed"
                result.warnings.append(msg)
                result.requirement_results["source_verification"] = (False, msg)
                return False

        except Exception as e:
            result.warnings.append(f"Source verification error: {str(e)}")
            result.requirement_results["source_verification"] = (False, str(e))
            return False

    def _verify_association(
        self,
        pool: PrivacyPool,
        set_id: str,
        address: str,
        secret: bytes,
        result: AMLVerificationResult
    ) -> bool:
        """验证关联证明"""
        try:
            # 获取关联集
            assoc_set = pool.get_association_set(set_id)
            if not assoc_set:
                result.errors.append(f"Association set {set_id} not found")
                return False

            # 检查关联集类型是否允许
            if self.policy.allowed_association_types:
                if assoc_set.set_type not in self.policy.allowed_association_types:
                    result.errors.append(
                        f"Association set type {assoc_set.set_type.value} not allowed"
                    )
                    return False

            # 生成关联证明
            proof = self.pool_prover.prove_association(pool, set_id, address, secret)

            if proof and proof.is_valid:
                result.association_proved = True
                result.association_proof = proof
                result.requirement_results["association_proof"] = (
                    True,
                    f"Associated with {assoc_set.name}"
                )
                return True
            else:
                result.association_proved = False
                result.errors.append("Failed to prove association")
                result.requirement_results["association_proof"] = (
                    False,
                    "Association proof failed"
                )
                return False

        except Exception as e:
            result.errors.append(f"Association verification error: {str(e)}")
            result.requirement_results["association_proof"] = (False, str(e))
            return False

    def _check_all_requirements(
        self,
        address: str,
        result: AMLVerificationResult
    ) -> None:
        """检查所有策略要求"""
        for req in self.policy.requirements:
            if req.requirement_type == AMLRequirementType.SANCTIONS_CHECK:
                # 已经在前面检查过
                continue

            elif req.requirement_type == AMLRequirementType.SOURCE_VERIFICATION:
                # 已经在前面检查过
                continue

            elif req.requirement_type == AMLRequirementType.ASSOCIATION_PROOF:
                # 已经在前面检查过
                continue

            elif req.requirement_type == AMLRequirementType.RISK_THRESHOLD:
                max_risk = req.params.get("max_risk", RiskLevel.MEDIUM)
                if result.overall_risk_level.value > max_risk.value:
                    result.requirement_results[req.name] = (
                        False,
                        f"Risk level {result.overall_risk_level.name} exceeds threshold"
                    )
                    if req.is_mandatory:
                        result.errors.append(f"Risk threshold exceeded: {req.name}")
                else:
                    result.requirement_results[req.name] = (True, "Risk within threshold")

            elif req.requirement_type == AMLRequirementType.VOLUME_LIMIT:
                # 这需要与外部交易数据集成
                result.requirement_results[req.name] = (True, "Volume check pending")
                result.warnings.append("Volume limit check requires external data")

            elif req.requirement_type == AMLRequirementType.VELOCITY_CHECK:
                result.requirement_results[req.name] = (True, "Velocity check pending")
                result.warnings.append("Velocity check requires external data")

            elif req.requirement_type == AMLRequirementType.GEOGRAPHIC_RESTRICTION:
                # 地理限制检查
                restricted = req.params.get("restricted_countries", [])
                result.requirement_results[req.name] = (True, "Geographic check passed")
                result.metadata["restricted_countries"] = restricted

            elif req.requirement_type == AMLRequirementType.TIME_RESTRICTION:
                # 时间限制检查
                result.requirement_results[req.name] = (True, "Time restriction passed")

    def _is_source_mandatory(self) -> bool:
        """检查来源验证是否为强制要求"""
        for req in self.policy.requirements:
            if req.requirement_type == AMLRequirementType.SOURCE_VERIFICATION:
                return req.is_mandatory
        return False

    def _is_association_mandatory(self) -> bool:
        """检查关联证明是否为强制要求"""
        for req in self.policy.requirements:
            if req.requirement_type == AMLRequirementType.ASSOCIATION_PROOF:
                return req.is_mandatory
        return False

    def _calculate_overall_risk(self, result: AMLVerificationResult) -> RiskLevel:
        """计算总体风险等级"""
        # 风险等级数值映射
        risk_values = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        risk_scores = []

        # 制裁检查失败 = 最高风险
        if not result.sanctions_check_passed:
            return RiskLevel.CRITICAL

        # 从来源证明获取风险
        if result.source_proof and result.source_proof.disclosed_risk_level:
            risk_scores.append(risk_values[result.source_proof.disclosed_risk_level])

        # 关联证明影响风险
        if result.association_proved:
            risk_scores.append(risk_values[RiskLevel.LOW])  # 有关联证明降低风险
        elif self._is_association_mandatory():
            risk_scores.append(risk_values[RiskLevel.HIGH])  # 缺少必需的关联证明

        # 计算平均风险
        if risk_scores:
            avg_risk = sum(risk_scores) / len(risk_scores)
            for level, value in risk_values.items():
                if value >= avg_risk:
                    return level

        return result.overall_risk_level

    def batch_verify(
        self,
        addresses: List[Tuple[str, bytes]]
    ) -> List[AMLVerificationResult]:
        """批量验证地址"""
        return [
            self.verify_address(addr, secret)
            for addr, secret in addresses
        ]

    def get_compliance_report(
        self,
        result: AMLVerificationResult
    ) -> Dict[str, Any]:
        """生成合规报告"""
        return {
            "verification_id": result.verification_id,
            "policy": {
                "id": self.policy.policy_id,
                "name": self.policy.name,
                "version": self.policy.version
            },
            "timestamp": result.timestamp.isoformat(),
            "overall_result": {
                "is_compliant": result.is_compliant,
                "risk_level": result.overall_risk_level.name
            },
            "checks": {
                "sanctions": {
                    "passed": result.sanctions_check_passed,
                    "proof_available": result.sanctions_proof is not None
                },
                "source": {
                    "verified": result.source_verified,
                    "proof_available": result.source_proof is not None
                },
                "association": {
                    "proved": result.association_proved,
                    "proof_available": result.association_proof is not None
                }
            },
            "requirement_results": {
                name: {"passed": passed, "message": msg}
                for name, (passed, msg) in result.requirement_results.items()
            },
            "errors": result.errors,
            "warnings": result.warnings,
            "metadata": result.metadata
        }


# 预定义策略

BASIC_AML_POLICY = AMLPolicy(
    policy_id="basic_aml_v1",
    name="Basic AML Policy",
    description="基础AML合规策略，适用于标准交易",
    requirements=[
        AMLRequirement(
            requirement_type=AMLRequirementType.SANCTIONS_CHECK,
            name="sanctions_check",
            description="检查地址是否在制裁名单",
            is_mandatory=True
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.RISK_THRESHOLD,
            name="risk_threshold",
            description="风险等级不超过MEDIUM",
            is_mandatory=True,
            params={"max_risk": RiskLevel.MEDIUM}
        )
    ],
    sanctions_lists=[
        SanctionsListType.OFAC_SDN,
        SanctionsListType.UN_SANCTIONS
    ],
    allowed_source_types={
        SourceType.CEX_WITHDRAWAL,
        SourceType.DEFI_SWAP,
        SourceType.BRIDGE,
        SourceType.NFT_SALE,
        SourceType.SALARY,
    },
    max_risk_level=RiskLevel.MEDIUM,
    jurisdiction="global"
)

STRICT_AML_POLICY = AMLPolicy(
    policy_id="strict_aml_v1",
    name="Strict AML Policy",
    description="严格AML合规策略，适用于大额或高风险交易",
    requirements=[
        AMLRequirement(
            requirement_type=AMLRequirementType.SANCTIONS_CHECK,
            name="sanctions_check",
            description="检查地址是否在制裁名单",
            is_mandatory=True
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.SOURCE_VERIFICATION,
            name="source_verification",
            description="验证资金来源",
            is_mandatory=True
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.ASSOCIATION_PROOF,
            name="association_proof",
            description="提供关联集证明",
            is_mandatory=True
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.RISK_THRESHOLD,
            name="risk_threshold",
            description="风险等级不超过LOW",
            is_mandatory=True,
            params={"max_risk": RiskLevel.LOW}
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.VOLUME_LIMIT,
            name="volume_limit",
            description="单笔交易不超过100 ETH",
            is_mandatory=False,
            params={"max_single": 100 * 10**18}
        )
    ],
    sanctions_lists=[
        SanctionsListType.OFAC_SDN,
        SanctionsListType.EU_SANCTIONS,
        SanctionsListType.UN_SANCTIONS
    ],
    allowed_source_types={
        SourceType.CEX_WITHDRAWAL,
        SourceType.SALARY,
    },
    allowed_association_types={
        AssociationSetType.COMPLIANT_EXCHANGES,
        AssociationSetType.INSTITUTIONAL,
        AssociationSetType.RETAIL_KYC
    },
    max_risk_level=RiskLevel.LOW,
    jurisdiction="global"
)

DEFI_AML_POLICY = AMLPolicy(
    policy_id="defi_aml_v1",
    name="DeFi AML Policy",
    description="DeFi场景AML策略，平衡合规与可用性",
    requirements=[
        AMLRequirement(
            requirement_type=AMLRequirementType.SANCTIONS_CHECK,
            name="sanctions_check",
            description="检查地址是否在制裁名单",
            is_mandatory=True
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.SOURCE_VERIFICATION,
            name="source_verification",
            description="验证资金来源(非强制)",
            is_mandatory=False,
            on_failure="warn"
        ),
        AMLRequirement(
            requirement_type=AMLRequirementType.RISK_THRESHOLD,
            name="risk_threshold",
            description="风险等级不超过HIGH",
            is_mandatory=True,
            params={"max_risk": RiskLevel.HIGH}
        )
    ],
    sanctions_lists=[
        SanctionsListType.OFAC_SDN
    ],
    allowed_source_types={
        SourceType.CEX_WITHDRAWAL,
        SourceType.DEFI_SWAP,
        SourceType.DEFI_LENDING,
        SourceType.DEFI_YIELD,
        SourceType.BRIDGE,
        SourceType.NFT_SALE,
        SourceType.AIRDROP
    },
    allowed_association_types={
        AssociationSetType.COMPLIANT_EXCHANGES,
        AssociationSetType.VERIFIED_DEFI,
        AssociationSetType.RETAIL_KYC
    },
    max_risk_level=RiskLevel.HIGH,
    jurisdiction="global"
)
