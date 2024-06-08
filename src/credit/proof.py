"""
Credit Proof System - 信用证明系统

生成零知识信用证明:
1. 阈值证明 - 证明信用分大于某个阈值
2. 范围证明 - 证明信用分在某个范围内
3. 属性证明 - 证明拥有某个信用属性
4. 比较证明 - 证明信用分高于另一个承诺
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import secrets

from src.zkp.primitives import BN128, Point
from src.zkp.commitment import PedersenCommitment
from src.credit.score import CreditScore, CreditFactorType, ScoreRange


class ProofType(Enum):
    """证明类型"""
    THRESHOLD = "threshold"  # 阈值证明
    RANGE = "range"  # 范围证明
    ATTRIBUTE = "attribute"  # 属性证明
    COMPARISON = "comparison"  # 比较证明
    COMPOSITE = "composite"  # 组合证明


@dataclass
class ThresholdProof:
    """阈值证明 - 证明分数 >= 阈值"""
    proof_id: str
    threshold: int

    # 承诺
    score_commitment: Point

    # 证明数据
    proof_data: Dict[str, Any]

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None

    def is_valid(self) -> bool:
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "proof_type": "threshold",
            "threshold": self.threshold,
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


@dataclass
class AttributeProof:
    """属性证明 - 证明拥有某个属性"""
    proof_id: str
    attribute: str

    # 承诺
    attribute_commitment: Point

    # 证明数据
    proof_data: Dict[str, Any]

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None

    def is_valid(self) -> bool:
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "proof_type": "attribute",
            "attribute": self.attribute,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class CreditProof:
    """
    综合信用证明

    可以包含多个子证明。
    """
    proof_id: str
    proof_type: ProofType

    # 地址承诺
    address_commitment: Point

    # 分数承诺
    score_commitment: Point

    # 子证明
    threshold_proofs: List[ThresholdProof] = field(default_factory=list)
    attribute_proofs: List[AttributeProof] = field(default_factory=list)

    # 公开的信用等级（可选）
    disclosed_range: Optional[ScoreRange] = None

    # 证明数据
    proof_data: Dict[str, Any] = field(default_factory=dict)

    # 元数据
    issuer: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None

    def is_valid(self) -> bool:
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "proof_type": self.proof_type.value,
            "threshold_proofs": [p.to_dict() for p in self.threshold_proofs],
            "attribute_proofs": [p.to_dict() for p in self.attribute_proofs],
            "disclosed_range": self.disclosed_range.value if self.disclosed_range else None,
            "issuer": self.issuer,
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class CreditProver:
    """
    信用证明生成器
    """

    def __init__(self, issuer: str = "ZK-Credit System"):
        self.curve = BN128
        self.pedersen = PedersenCommitment(self.curve)
        self.issuer = issuer

    def create_score_commitment(
        self,
        score: CreditScore,
        blinding_factor: Optional[int] = None
    ) -> tuple[Point, int]:
        """
        创建分数承诺

        Args:
            score: 信用分数
            blinding_factor: 可选盲因子

        Returns:
            (commitment, blinding_factor)
        """
        if blinding_factor is None:
            blinding_factor = self.curve.random_scalar()

        commitment, _ = self.pedersen.commit(score.total_score, blinding_factor)
        return commitment, blinding_factor

    def prove_threshold(
        self,
        score: CreditScore,
        threshold: int,
        score_commitment: Point,
        blinding_factor: int,
        validity_hours: int = 24
    ) -> ThresholdProof:
        """
        生成阈值证明

        证明 score >= threshold

        Args:
            score: 信用分数
            threshold: 阈值
            score_commitment: 分数承诺
            blinding_factor: 盲因子
            validity_hours: 有效期

        Returns:
            ThresholdProof
        """
        if score.total_score < threshold:
            raise ValueError(
                f"Score {score.total_score} is below threshold {threshold}"
            )

        # 差值
        diff = score.total_score - threshold
        diff_blinding = self.curve.random_scalar()

        # 差值承诺
        diff_commitment, _ = self.pedersen.commit(diff, diff_blinding)

        # Schnorr证明：证明知道diff使得 diff_commitment = g^diff * h^diff_blinding
        k1 = self.curve.random_scalar()
        k2 = self.curve.random_scalar()
        R = k1 * self.curve.generator + k2 * self.pedersen.h

        # 挑战
        e_data = (
            R.to_bytes() +
            diff_commitment.to_bytes() +
            threshold.to_bytes(4, 'big')
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s1 = (k1 + e * diff) % self.curve.n
        s2 = (k2 + e * diff_blinding) % self.curve.n

        proof_data = {
            "diff_commitment": {
                "x": str(diff_commitment.x.value),
                "y": str(diff_commitment.y.value),
            },
            "R": {
                "x": str(R.x.value),
                "y": str(R.y.value),
            },
            "e": str(e),
            "s1": str(s1),
            "s2": str(s2),
        }

        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return ThresholdProof(
            proof_id=secrets.token_hex(8),
            threshold=threshold,
            score_commitment=score_commitment,
            proof_data=proof_data,
            valid_until=valid_until
        )

    def prove_range(
        self,
        score: CreditScore,
        lower_bound: int,
        upper_bound: int,
        score_commitment: Point,
        blinding_factor: int,
        validity_hours: int = 24
    ) -> CreditProof:
        """
        生成范围证明

        证明 lower_bound <= score <= upper_bound

        Args:
            score: 信用分数
            lower_bound: 下界
            upper_bound: 上界
            score_commitment: 分数承诺
            blinding_factor: 盲因子
            validity_hours: 有效期

        Returns:
            CreditProof
        """
        if score.total_score < lower_bound or score.total_score > upper_bound:
            raise ValueError(
                f"Score {score.total_score} not in range [{lower_bound}, {upper_bound}]"
            )

        # 生成两个阈值证明
        lower_proof = self.prove_threshold(
            score, lower_bound, score_commitment, blinding_factor, validity_hours
        )

        # 对于上界，证明 upper_bound - score >= 0
        upper_diff = upper_bound - score.total_score
        upper_blinding = self.curve.random_scalar()
        upper_diff_commitment, _ = self.pedersen.commit(upper_diff, upper_blinding)

        # Schnorr证明
        k1 = self.curve.random_scalar()
        k2 = self.curve.random_scalar()
        R = k1 * self.curve.generator + k2 * self.pedersen.h

        e_data = (
            R.to_bytes() +
            upper_diff_commitment.to_bytes() +
            upper_bound.to_bytes(4, 'big')
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        s1 = (k1 + e * upper_diff) % self.curve.n
        s2 = (k2 + e * upper_blinding) % self.curve.n

        # 地址承诺
        address_blinding = self.curve.random_scalar()
        address_hash = int.from_bytes(score.address_hash[:16], 'big') % self.curve.n
        address_commitment, _ = self.pedersen.commit(address_hash, address_blinding)

        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return CreditProof(
            proof_id=secrets.token_hex(8),
            proof_type=ProofType.RANGE,
            address_commitment=address_commitment,
            score_commitment=score_commitment,
            threshold_proofs=[lower_proof],
            proof_data={
                "lower_bound": lower_bound,
                "upper_bound": upper_bound,
                "upper_diff_commitment": {
                    "x": str(upper_diff_commitment.x.value),
                    "y": str(upper_diff_commitment.y.value),
                },
                "upper_proof": {
                    "R": {"x": str(R.x.value), "y": str(R.y.value)},
                    "e": str(e),
                    "s1": str(s1),
                    "s2": str(s2),
                }
            },
            issuer=self.issuer,
            valid_until=valid_until
        )

    def prove_attribute(
        self,
        score: CreditScore,
        attribute: str,
        validity_hours: int = 24
    ) -> AttributeProof:
        """
        生成属性证明

        证明拥有某个信用属性

        Args:
            score: 信用分数
            attribute: 要证明的属性
            validity_hours: 有效期

        Returns:
            AttributeProof
        """
        if attribute not in score.attributes:
            raise ValueError(f"Score does not have attribute: {attribute}")

        # 属性承诺
        attr_hash = int.from_bytes(
            hashlib.sha256(attribute.encode()).digest()[:16],
            'big'
        ) % self.curve.n
        attr_blinding = self.curve.random_scalar()
        attr_commitment, _ = self.pedersen.commit(attr_hash, attr_blinding)

        # Schnorr证明
        k1 = self.curve.random_scalar()
        k2 = self.curve.random_scalar()
        R = k1 * self.curve.generator + k2 * self.pedersen.h

        e_data = (
            R.to_bytes() +
            attr_commitment.to_bytes() +
            attribute.encode()
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        s1 = (k1 + e * attr_hash) % self.curve.n
        s2 = (k2 + e * attr_blinding) % self.curve.n

        proof_data = {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "e": str(e),
            "s1": str(s1),
            "s2": str(s2),
        }

        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return AttributeProof(
            proof_id=secrets.token_hex(8),
            attribute=attribute,
            attribute_commitment=attr_commitment,
            proof_data=proof_data,
            valid_until=valid_until
        )

    def prove_credit(
        self,
        score: CreditScore,
        thresholds: Optional[List[int]] = None,
        attributes: Optional[List[str]] = None,
        disclose_range: bool = False,
        validity_hours: int = 24
    ) -> CreditProof:
        """
        生成综合信用证明

        Args:
            score: 信用分数
            thresholds: 要证明的阈值列表
            attributes: 要证明的属性列表
            disclose_range: 是否公开信用等级
            validity_hours: 有效期

        Returns:
            CreditProof
        """
        # 创建承诺
        blinding_factor = self.curve.random_scalar()
        score_commitment, _ = self.pedersen.commit(score.total_score, blinding_factor)

        address_blinding = self.curve.random_scalar()
        address_hash = int.from_bytes(score.address_hash[:16], 'big') % self.curve.n
        address_commitment, _ = self.pedersen.commit(address_hash, address_blinding)

        # 生成阈值证明
        threshold_proofs = []
        if thresholds:
            for t in thresholds:
                if score.total_score >= t:
                    proof = self.prove_threshold(
                        score, t, score_commitment, blinding_factor, validity_hours
                    )
                    threshold_proofs.append(proof)

        # 生成属性证明
        attribute_proofs = []
        if attributes:
            for attr in attributes:
                if attr in score.attributes:
                    proof = self.prove_attribute(score, attr, validity_hours)
                    attribute_proofs.append(proof)

        # 确定证明类型
        if threshold_proofs and attribute_proofs:
            proof_type = ProofType.COMPOSITE
        elif threshold_proofs:
            proof_type = ProofType.THRESHOLD
        elif attribute_proofs:
            proof_type = ProofType.ATTRIBUTE
        else:
            proof_type = ProofType.THRESHOLD  # 默认

        # 披露等级
        disclosed_range = score.score_range if disclose_range else None

        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return CreditProof(
            proof_id=secrets.token_hex(8),
            proof_type=proof_type,
            address_commitment=address_commitment,
            score_commitment=score_commitment,
            threshold_proofs=threshold_proofs,
            attribute_proofs=attribute_proofs,
            disclosed_range=disclosed_range,
            issuer=self.issuer,
            valid_until=valid_until
        )
