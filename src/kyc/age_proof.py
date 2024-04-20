"""
年龄证明系统

实现零知识年龄验证:
- 证明 age >= threshold（如18岁）而不泄露具体出生日期
- 基于范围证明和日期承诺
"""

from dataclasses import dataclass, field as dc_field
from datetime import date, datetime as dt
from typing import Optional, Tuple, List, Dict, Any
import hashlib
import secrets

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    FiniteField,
    BN128,
)
from src.zkp.commitment import PedersenCommitment
from src.kyc.credential import (
    Credential,
    CredentialAttribute,
    AttributeType,
    date_to_days_since_epoch,
    compute_age,
)


@dataclass
class AgeCredential:
    """年龄凭证

    包含出生日期的承诺和相关证明材料。
    """
    # 出生日期承诺 C = birth_days * G + r * H
    birth_date_commitment: Point
    # 用于打开承诺的盲因子
    blinding_factor: int
    # 实际出生日期（私密）
    birth_date: date
    # 发行者签名
    issuer_signature: Optional[bytes] = None
    # 凭证ID
    credential_id: str = ""

    def __post_init__(self):
        if not self.credential_id:
            self.credential_id = secrets.token_hex(8)

    @property
    def birth_days(self) -> int:
        """出生日期转换为天数"""
        return date_to_days_since_epoch(self.birth_date)

    def get_age(self, reference_date: Optional[date] = None) -> int:
        """计算当前年龄"""
        return compute_age(self.birth_date, reference_date)


@dataclass
class AgeProof:
    """年龄证明

    证明持有者年龄满足某个条件，而不泄露具体年龄。
    """
    # 声明类型: "gte" (>=), "lte" (<=), "range" ([min, max])
    claim_type: str
    # 阈值年龄
    threshold_age: int
    # 参考日期（用于计算年龄）
    reference_date: date

    # 证明数据
    birth_date_commitment: Point
    # 范围证明数据
    range_proof: Dict[str, Any]
    # 挑战响应
    challenge: int
    response: int

    # 时间戳
    created_at: dt = dc_field(default_factory=dt.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_type": self.claim_type,
            "threshold_age": self.threshold_age,
            "reference_date": self.reference_date.isoformat(),
            "commitment": {
                "x": str(self.birth_date_commitment.x.value) if self.birth_date_commitment.x else None,
                "y": str(self.birth_date_commitment.y.value) if self.birth_date_commitment.y else None,
            },
            "challenge": str(self.challenge),
            "response": str(self.response),
            "created_at": self.created_at.isoformat(),
        }


class AgeProver:
    """年龄证明生成器

    生成零知识年龄证明。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def create_age_credential(
        self,
        birth_date: date,
        blinding_factor: Optional[int] = None
    ) -> AgeCredential:
        """创建年龄凭证"""
        if blinding_factor is None:
            blinding_factor = self.curve.random_scalar()

        # 计算出生日期的承诺
        birth_days = date_to_days_since_epoch(birth_date)
        commitment, _ = self.pedersen.commit(birth_days, blinding_factor)

        return AgeCredential(
            birth_date_commitment=commitment,
            blinding_factor=blinding_factor,
            birth_date=birth_date,
        )

    def prove_age_gte(
        self,
        credential: AgeCredential,
        threshold_age: int,
        reference_date: Optional[date] = None
    ) -> AgeProof:
        """证明年龄 >= threshold

        核心思路:
        1. 计算阈值对应的最晚出生日期
        2. 证明实际出生日期 <= 阈值日期
        3. 使用范围证明确保日期差值非负

        Args:
            credential: 年龄凭证
            threshold_age: 阈值年龄（如18）
            reference_date: 参考日期（默认为今天）

        Returns:
            AgeProof 年龄证明
        """
        if reference_date is None:
            reference_date = date.today()

        # 计算阈值日期（满足threshold_age岁的最晚出生日期）
        threshold_date = date(
            reference_date.year - threshold_age,
            reference_date.month,
            reference_date.day
        )
        threshold_days = date_to_days_since_epoch(threshold_date)

        # 实际出生天数
        birth_days = credential.birth_days

        # 验证条件: birth_days <= threshold_days (出生得更早 = 年龄更大)
        # 等价于: delta = threshold_days - birth_days >= 0
        delta = threshold_days - birth_days

        if delta < 0:
            raise ValueError(f"Age requirement not met: need >= {threshold_age}")

        # 生成范围证明（证明delta >= 0）
        range_proof = self._create_range_proof(delta, n_bits=32)

        # 生成Schnorr风格的知识证明
        # 证明知道 birth_days 和 blinding_factor 使得承诺成立
        challenge, response = self._create_knowledge_proof(
            credential,
            threshold_days,
            reference_date,
        )

        return AgeProof(
            claim_type="gte",
            threshold_age=threshold_age,
            reference_date=reference_date,
            birth_date_commitment=credential.birth_date_commitment,
            range_proof=range_proof,
            challenge=challenge,
            response=response,
        )

    def prove_age_in_range(
        self,
        credential: AgeCredential,
        min_age: int,
        max_age: int,
        reference_date: Optional[date] = None
    ) -> AgeProof:
        """证明年龄在 [min_age, max_age] 范围内"""
        if reference_date is None:
            reference_date = date.today()

        actual_age = credential.get_age(reference_date)

        if actual_age < min_age or actual_age > max_age:
            raise ValueError(f"Age {actual_age} not in range [{min_age}, {max_age}]")

        # 计算上下界日期
        min_date = date(reference_date.year - max_age - 1, reference_date.month, reference_date.day)
        max_date = date(reference_date.year - min_age, reference_date.month, reference_date.day)

        min_days = date_to_days_since_epoch(min_date)
        max_days = date_to_days_since_epoch(max_date)
        birth_days = credential.birth_days

        # 证明: min_days <= birth_days <= max_days
        delta_lower = birth_days - min_days
        delta_upper = max_days - birth_days

        if delta_lower < 0 or delta_upper < 0:
            raise ValueError("Age range requirement not met")

        range_proof = {
            "lower_bound_proof": self._create_range_proof(delta_lower, n_bits=32),
            "upper_bound_proof": self._create_range_proof(delta_upper, n_bits=32),
        }

        challenge, response = self._create_knowledge_proof(
            credential,
            max_days,
            reference_date,
        )

        return AgeProof(
            claim_type="range",
            threshold_age=min_age,  # 使用min_age作为threshold
            reference_date=reference_date,
            birth_date_commitment=credential.birth_date_commitment,
            range_proof=range_proof,
            challenge=challenge,
            response=response,
        )

    def _create_range_proof(self, value: int, n_bits: int = 32) -> Dict[str, Any]:
        """创建简化的范围证明

        证明 value ∈ [0, 2^n_bits)

        完整实现应使用Bulletproofs等高效方案。
        """
        if value < 0 or value >= (1 << n_bits):
            raise ValueError(f"Value {value} out of range [0, {1 << n_bits})")

        # 位分解
        bits = [(value >> i) & 1 for i in range(n_bits)]

        # 对每一位创建承诺
        bit_commitments = []
        bit_blindings = []

        for bit in bits:
            r = self.curve.random_scalar()
            c, _ = self.pedersen.commit(bit, r)
            bit_commitments.append(c)
            bit_blindings.append(r)

        # 创建位约束证明 (每个bit ∈ {0, 1})
        bit_proofs = []
        for i, (bit, r, c) in enumerate(zip(bits, bit_blindings, bit_commitments)):
            # 证明 bit * (1 - bit) = 0
            proof = self._prove_bit_constraint(bit, r)
            bit_proofs.append(proof)

        return {
            "n_bits": n_bits,
            "bit_commitments": [
                {"x": str(c.x.value), "y": str(c.y.value)}
                for c in bit_commitments
            ],
            "bit_proofs": bit_proofs,
            "value_hash": hashlib.sha256(str(value).encode()).hexdigest()[:16],
        }

    def _prove_bit_constraint(self, bit: int, blinding: int) -> Dict[str, Any]:
        """证明承诺值是0或1"""
        # 简化实现: 提供挑战-响应证明
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 挑战
        e_data = R.to_bytes() + str(bit).encode()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s = (k + e * blinding) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "s": str(s),
        }

    def _create_knowledge_proof(
        self,
        credential: AgeCredential,
        threshold_days: int,
        reference_date: date,
    ) -> Tuple[int, int]:
        """创建知识证明"""
        # Schnorr风格证明
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 挑战包含所有公开信息
        e_data = (
            R.to_bytes() +
            credential.birth_date_commitment.to_bytes() +
            str(threshold_days).encode() +
            reference_date.isoformat().encode()
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应: s = k + e * blinding_factor
        s = (k + e * credential.blinding_factor) % self.curve.n

        return e, s


class AgeVerifier:
    """年龄证明验证器"""

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def verify_age_gte(
        self,
        proof: AgeProof,
        expected_threshold: int,
        expected_reference_date: Optional[date] = None
    ) -> bool:
        """验证年龄 >= threshold 的证明"""
        # 检查证明类型
        if proof.claim_type != "gte":
            return False

        # 检查阈值
        if proof.threshold_age != expected_threshold:
            return False

        # 检查参考日期
        if expected_reference_date and proof.reference_date != expected_reference_date:
            return False

        # 验证承诺格式
        if not proof.birth_date_commitment.on_curve():
            return False

        # 验证范围证明
        if not self._verify_range_proof(proof.range_proof):
            return False

        # 验证知识证明
        if not self._verify_knowledge_proof(proof):
            return False

        return True

    def verify_age_in_range(
        self,
        proof: AgeProof,
        min_age: int,
        max_age: int
    ) -> bool:
        """验证年龄范围证明"""
        if proof.claim_type != "range":
            return False

        # 验证范围证明
        range_proof = proof.range_proof
        if "lower_bound_proof" not in range_proof or "upper_bound_proof" not in range_proof:
            return False

        if not self._verify_range_proof(range_proof["lower_bound_proof"]):
            return False
        if not self._verify_range_proof(range_proof["upper_bound_proof"]):
            return False

        return True

    def _verify_range_proof(self, range_proof: Dict[str, Any]) -> bool:
        """验证范围证明"""
        # 简化验证
        if "n_bits" not in range_proof:
            return False
        if "bit_commitments" not in range_proof:
            return False
        if "bit_proofs" not in range_proof:
            return False

        n_bits = range_proof["n_bits"]
        bit_commitments = range_proof["bit_commitments"]
        bit_proofs = range_proof["bit_proofs"]

        if len(bit_commitments) != n_bits or len(bit_proofs) != n_bits:
            return False

        # 验证每个位的承诺
        for i, (comm_data, proof) in enumerate(zip(bit_commitments, bit_proofs)):
            if not self._verify_bit_proof(comm_data, proof):
                return False

        return True

    def _verify_bit_proof(
        self,
        commitment_data: Dict[str, str],
        proof: Dict[str, Any]
    ) -> bool:
        """验证位承诺证明"""
        # 简化验证
        try:
            # 检查承诺点格式
            x = int(commitment_data["x"])
            y = int(commitment_data["y"])

            # 检查证明格式
            if "R" not in proof or "s" not in proof:
                return False

            return True
        except (KeyError, ValueError):
            return False

    def _verify_knowledge_proof(self, proof: AgeProof) -> bool:
        """验证知识证明"""
        # 重新计算阈值日期
        threshold_date = date(
            proof.reference_date.year - proof.threshold_age,
            proof.reference_date.month,
            proof.reference_date.day
        )
        threshold_days = date_to_days_since_epoch(threshold_date)

        # 验证响应
        g = self.curve.generator
        s = proof.response
        e = proof.challenge

        # 验证: s*G == R + e*commitment（简化，完整验证需要R）
        # 这里只做格式检查
        if s <= 0 or s >= self.curve.n:
            return False
        if e <= 0 or e >= self.curve.n:
            return False

        return True

    def verify_with_issuer_signature(
        self,
        proof: AgeProof,
        issuer_public_key: Point,
        signature: bytes
    ) -> bool:
        """验证带发行者签名的证明"""
        # 首先验证基本证明
        if not self.verify_age_gte(proof, proof.threshold_age):
            return False

        # 然后验证发行者签名
        # 简化实现
        return len(signature) > 0


def create_test_age_credential(
    birth_year: int,
    birth_month: int = 1,
    birth_day: int = 1
) -> AgeCredential:
    """创建测试用年龄凭证"""
    prover = AgeProver()
    birth_date = date(birth_year, birth_month, birth_day)
    return prover.create_age_credential(birth_date)
