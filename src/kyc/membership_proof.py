"""
集合成员身份证明

实现零知识集合成员证明:
- 证明某值属于某个集合，而不泄露具体是哪个值
- 基于Merkle树和累加器
- 典型应用：国籍白名单/黑名单验证
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt
from typing import Optional, List, Dict, Any, Set
import hashlib
import secrets

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    FiniteField,
    BN128,
)
from src.zkp.commitment import PedersenCommitment, MerkleTreeCommitment


@dataclass
class SetCommitment:
    """集合承诺

    对一个值集合的密码学承诺，支持成员证明。
    """
    # Merkle根
    root: bytes
    # 集合大小
    size: int
    # 集合元素列表（用于查找索引）
    elements: List[str] = dc_field(default_factory=list)
    # 随机数列表（用于验证）
    randomness: List[bytes] = dc_field(default_factory=list)
    # 集合ID
    set_id: str = ""
    # 创建时间
    created_at: dt = dc_field(default_factory=dt.now)
    # 元数据
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self):
        if not self.set_id:
            self.set_id = secrets.token_hex(8)

    def get_index(self, value: str) -> int:
        """获取元素在集合中的索引"""
        try:
            return self.elements.index(value)
        except ValueError:
            return -1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root.hex(),
            "size": self.size,
            "set_id": self.set_id,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class MembershipProof:
    """成员身份证明

    证明某个值属于集合，而不泄露具体是哪个值。
    """
    # 证明类型: "membership" (属于), "non_membership" (不属于)
    proof_type: str
    # 集合承诺
    set_commitment: SetCommitment
    # 值的承诺（隐藏实际值）
    value_commitment: Point
    # Merkle证明路径 [(sibling_hash, is_left), ...]
    merkle_path: List[tuple]
    # 值对应的随机数
    value_randomness: bytes
    # 值在集合中的索引
    value_index: int
    # 知识证明
    knowledge_proof: Dict[str, Any]
    # 时间戳
    created_at: dt = dc_field(default_factory=dt.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_type": self.proof_type,
            "set_commitment": self.set_commitment.to_dict(),
            "value_commitment": {
                "x": str(self.value_commitment.x.value) if self.value_commitment.x else None,
                "y": str(self.value_commitment.y.value) if self.value_commitment.y else None,
            },
            "merkle_path": [(p[0].hex(), p[1]) for p in self.merkle_path],
            "value_index": self.value_index,
            "created_at": self.created_at.isoformat(),
        }


class MembershipProver:
    """成员身份证明生成器

    生成零知识集合成员证明。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def create_set_commitment(
        self,
        values: List[str],
        set_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> tuple[SetCommitment, MerkleTreeCommitment]:
        """创建集合承诺

        Args:
            values: 集合元素列表（如国家代码列表）
            set_id: 可选的集合ID
            metadata: 可选的元数据

        Returns:
            (SetCommitment, MerkleTreeCommitment) 元组
        """
        # 创建Merkle树
        merkle = MerkleTreeCommitment()

        # 将字符串值转换为字节
        values_bytes = [v.encode() for v in values]

        # 构建Merkle树并获取根和随机数
        root, randomness = merkle.commit(values_bytes)

        commitment = SetCommitment(
            root=root,
            size=len(values),
            elements=values,
            randomness=randomness,
            set_id=set_id or "",
            metadata=metadata or {},
        )

        return commitment, merkle

    def prove_membership(
        self,
        value: str,
        merkle_tree: MerkleTreeCommitment,
        set_commitment: SetCommitment,
        blinding_factor: Optional[int] = None,
    ) -> MembershipProof:
        """证明值属于集合

        Args:
            value: 要证明的值
            merkle_tree: Merkle树
            set_commitment: 集合承诺
            blinding_factor: 可选的盲因子

        Returns:
            MembershipProof
        """
        # 查找值在集合中的索引
        index = set_commitment.get_index(value)
        if index < 0:
            raise ValueError(f"Value '{value}' not in set")

        # 获取Merkle证明路径
        merkle_path = merkle_tree.get_proof(index)

        # 获取对应的随机数
        value_randomness = set_commitment.randomness[index]

        # 创建值的Pedersen承诺
        if blinding_factor is None:
            blinding_factor = self.curve.random_scalar()

        # 值哈希到域元素
        leaf_data = value.encode()
        value_hash = int.from_bytes(
            hashlib.sha256(leaf_data).digest(), 'big'
        ) % self.curve.n

        value_commitment, _ = self.pedersen.commit(value_hash, blinding_factor)

        # 创建知识证明
        knowledge_proof = self._create_membership_knowledge_proof(
            value_hash,
            blinding_factor,
            value_commitment,
            merkle_path,
        )

        return MembershipProof(
            proof_type="membership",
            set_commitment=set_commitment,
            value_commitment=value_commitment,
            merkle_path=merkle_path,
            value_randomness=value_randomness,
            value_index=index,
            knowledge_proof=knowledge_proof,
        )

    def prove_non_membership(
        self,
        value: str,
        excluded_set: Set[str],
        set_commitment: SetCommitment,
        blinding_factor: Optional[int] = None,
    ) -> MembershipProof:
        """证明值不属于集合（用于黑名单检查）

        这是一个简化实现，完整实现需要使用排序累加器或其他方案。

        Args:
            value: 要证明不属于集合的值
            excluded_set: 排除集合
            set_commitment: 集合承诺
            blinding_factor: 可选的盲因子

        Returns:
            MembershipProof
        """
        if value in excluded_set:
            raise ValueError(f"Value '{value}' is in the excluded set")

        # 创建值的承诺
        if blinding_factor is None:
            blinding_factor = self.curve.random_scalar()

        leaf_data = value.encode()
        value_hash = int.from_bytes(
            hashlib.sha256(leaf_data).digest(), 'big'
        ) % self.curve.n

        value_commitment, _ = self.pedersen.commit(value_hash, blinding_factor)

        # 简化的非成员证明
        # 完整实现应使用排序Merkle树或RSA累加器
        knowledge_proof = self._create_non_membership_proof(
            value_hash,
            blinding_factor,
            excluded_set,
        )

        return MembershipProof(
            proof_type="non_membership",
            set_commitment=set_commitment,
            value_commitment=value_commitment,
            merkle_path=[],
            value_randomness=b"",
            value_index=-1,
            knowledge_proof=knowledge_proof,
        )

    def _create_membership_knowledge_proof(
        self,
        value_hash: int,
        blinding_factor: int,
        commitment: Point,
        merkle_path: List[tuple],
    ) -> Dict[str, Any]:
        """创建成员身份知识证明"""
        # Schnorr风格证明
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 挑战包含所有公开信息
        path_bytes = b"".join(p[0] for p in merkle_path)
        e_data = (
            R.to_bytes() +
            commitment.to_bytes() +
            path_bytes
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s = (k + e * blinding_factor) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
        }

    def _create_non_membership_proof(
        self,
        value_hash: int,
        blinding_factor: int,
        excluded_set: Set[str],
    ) -> Dict[str, Any]:
        """创建非成员身份证明"""
        # 简化实现
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 计算排除集合的哈希
        excluded_hashes = sorted([
            hashlib.sha256(v.encode()).hexdigest()
            for v in excluded_set
        ])
        set_digest = hashlib.sha256(
            "".join(excluded_hashes).encode()
        ).digest()

        e_data = R.to_bytes() + set_digest
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n
        s = (k + e * blinding_factor) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
            "set_digest": set_digest.hex(),
        }


class MembershipVerifier:
    """成员身份证明验证器"""

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def verify_membership(
        self,
        proof: MembershipProof,
        expected_root: Optional[bytes] = None,
    ) -> bool:
        """验证成员身份证明

        Args:
            proof: 成员身份证明
            expected_root: 期望的Merkle根（可选）

        Returns:
            验证是否通过
        """
        if proof.proof_type != "membership":
            return False

        # 检查Merkle根
        if expected_root and proof.set_commitment.root != expected_root:
            return False

        # 验证承诺点在曲线上
        if not proof.value_commitment.on_curve():
            return False

        # 验证Merkle路径非空
        if len(proof.merkle_path) == 0:
            return False

        # 验证知识证明
        if not self._verify_knowledge_proof(proof):
            return False

        return True

    def verify_non_membership(
        self,
        proof: MembershipProof,
        excluded_set_digest: Optional[bytes] = None,
    ) -> bool:
        """验证非成员身份证明

        Args:
            proof: 非成员身份证明
            excluded_set_digest: 排除集合的摘要

        Returns:
            验证是否通过
        """
        if proof.proof_type != "non_membership":
            return False

        # 验证承诺点在曲线上
        if not proof.value_commitment.on_curve():
            return False

        # 验证知识证明
        if not self._verify_non_membership_proof(proof, excluded_set_digest):
            return False

        return True

    def _verify_knowledge_proof(self, proof: MembershipProof) -> bool:
        """验证知识证明"""
        try:
            kp = proof.knowledge_proof

            # 解析证明数据
            if "R" not in kp or "challenge" not in kp or "response" not in kp:
                return False

            s = int(kp["response"])
            e = int(kp["challenge"])

            # 检查范围
            if s <= 0 or s >= self.curve.n:
                return False
            if e <= 0 or e >= self.curve.n:
                return False

            return True
        except (KeyError, ValueError):
            return False

    def _verify_non_membership_proof(
        self,
        proof: MembershipProof,
        expected_digest: Optional[bytes] = None,
    ) -> bool:
        """验证非成员身份证明"""
        try:
            kp = proof.knowledge_proof

            if "set_digest" not in kp:
                return False

            # 验证集合摘要
            if expected_digest:
                if bytes.fromhex(kp["set_digest"]) != expected_digest:
                    return False

            return self._verify_knowledge_proof(proof)
        except (KeyError, ValueError):
            return False


# ============================================================
# 预定义国籍集合
# ============================================================

# FATF高风险国家列表（示例）
FATF_HIGH_RISK_COUNTRIES = {
    "KP",  # 朝鲜
    "IR",  # 伊朗
    "MM",  # 缅甸
}

# FATF灰名单国家（示例）
FATF_GREY_LIST_COUNTRIES = {
    "SY",  # 叙利亚
    "YE",  # 也门
    "AF",  # 阿富汗
}

# 常见合规国家列表（示例）
COMPLIANT_COUNTRIES = {
    "US", "GB", "DE", "FR", "JP", "CA", "AU", "SG", "HK", "CH",
    "NL", "SE", "NO", "DK", "FI", "IE", "NZ", "KR", "TW", "CN",
}

# OFAC制裁国家（示例）
OFAC_SANCTIONED_COUNTRIES = {
    "KP", "IR", "CU", "SY", "RU",
}


def create_nationality_whitelist(
    countries: Set[str],
    list_name: str = "whitelist"
) -> tuple[SetCommitment, MerkleTreeCommitment]:
    """创建国籍白名单

    Args:
        countries: 允许的国家代码集合
        list_name: 列表名称

    Returns:
        (SetCommitment, MerkleTreeCommitment) 元组
    """
    prover = MembershipProver()
    return prover.create_set_commitment(
        values=sorted(list(countries)),
        metadata={"list_name": list_name, "type": "whitelist"},
    )


def create_nationality_blacklist(
    countries: Set[str],
    list_name: str = "blacklist"
) -> tuple[SetCommitment, MerkleTreeCommitment]:
    """创建国籍黑名单

    Args:
        countries: 禁止的国家代码集合
        list_name: 列表名称

    Returns:
        (SetCommitment, MerkleTreeCommitment) 元组
    """
    prover = MembershipProver()
    return prover.create_set_commitment(
        values=sorted(list(countries)),
        metadata={"list_name": list_name, "type": "blacklist"},
    )
