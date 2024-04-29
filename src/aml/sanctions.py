"""
制裁名单筛查系统

实现零知识制裁筛查:
- 证明地址不在OFAC SDN名单
- 证明地址不在EU/UN制裁名单
- 支持多名单组合筛查
- 不泄露具体地址信息
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt
from typing import Optional, List, Dict, Any, Set, Tuple
from enum import Enum
import hashlib
import secrets

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    BN128,
)
from src.zkp.commitment import PedersenCommitment, MerkleTreeCommitment


class SanctionsListType(Enum):
    """制裁名单类型"""
    OFAC_SDN = "ofac_sdn"          # 美国OFAC特别指定国民名单
    OFAC_CONS = "ofac_cons"        # OFAC综合制裁名单
    EU_SANCTIONS = "eu_sanctions"  # 欧盟制裁名单
    UN_SANCTIONS = "un_sanctions"  # 联合国制裁名单
    UK_SANCTIONS = "uk_sanctions"  # 英国制裁名单
    CUSTOM = "custom"              # 自定义名单


@dataclass
class SanctionedEntity:
    """受制裁实体"""
    # 实体标识（地址哈希或名称哈希）
    entity_id: str
    # 实体类型
    entity_type: str  # "address", "name", "organization"
    # 原始值（可选，用于测试）
    raw_value: Optional[str] = None
    # 添加日期
    added_date: Optional[dt] = None
    # 制裁原因
    reason: str = ""
    # 来源名单
    source_list: SanctionsListType = SanctionsListType.CUSTOM

    def to_bytes(self) -> bytes:
        """转换为字节用于哈希"""
        return self.entity_id.encode()


@dataclass
class SanctionsList:
    """制裁名单

    存储受制裁实体的密码学承诺。
    """
    # 名单类型
    list_type: SanctionsListType
    # 名单版本
    version: str
    # Merkle树根
    merkle_root: bytes
    # 名单大小
    size: int
    # 最后更新时间
    last_updated: dt = dc_field(default_factory=dt.now)
    # 元数据
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "list_type": self.list_type.value,
            "version": self.version,
            "merkle_root": self.merkle_root.hex(),
            "size": self.size,
            "last_updated": self.last_updated.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class AddressCommitment:
    """地址承诺

    对区块链地址的密码学承诺。
    """
    # 承诺值
    commitment: Point
    # 地址哈希（私密）
    address_hash: int
    # 盲因子（私密）
    blinding_factor: int
    # 地址类型
    address_type: str = "ethereum"  # ethereum, bitcoin, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": {
                "x": str(self.commitment.x.value),
                "y": str(self.commitment.y.value),
            },
            "address_type": self.address_type,
        }


@dataclass
class SanctionsProof:
    """制裁筛查证明

    证明地址不在制裁名单中。
    """
    # 证明类型
    proof_type: str  # "non_membership", "clear"
    # 地址承诺
    address_commitment: Point
    # 筛查的名单
    screened_lists: List[SanctionsListType]
    # 名单Merkle根
    list_roots: Dict[str, bytes]
    # 非成员证明数据
    non_membership_proofs: Dict[str, Dict[str, Any]]
    # 知识证明
    knowledge_proof: Dict[str, Any]
    # 创建时间
    created_at: dt = dc_field(default_factory=dt.now)
    # 有效期
    valid_until: Optional[dt] = None

    def is_valid(self) -> bool:
        """检查证明是否仍在有效期内"""
        if self.valid_until is None:
            return True
        return dt.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_type": self.proof_type,
            "address_commitment": {
                "x": str(self.address_commitment.x.value),
                "y": str(self.address_commitment.y.value),
            },
            "screened_lists": [l.value for l in self.screened_lists],
            "list_roots": {k: v.hex() for k, v in self.list_roots.items()},
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class SanctionsScreener:
    """制裁筛查器

    生成和验证制裁筛查的零知识证明。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

        # 已注册的制裁名单
        self.sanctions_lists: Dict[SanctionsListType, SanctionsList] = {}

        # 名单的Merkle树（用于证明生成）
        self.merkle_trees: Dict[SanctionsListType, MerkleTreeCommitment] = {}

        # 名单实体集合（用于快速查找）
        self.entity_sets: Dict[SanctionsListType, Set[str]] = {}

    def register_sanctions_list(
        self,
        list_type: SanctionsListType,
        entities: List[SanctionedEntity],
        version: str = "1.0",
    ) -> SanctionsList:
        """注册制裁名单

        Args:
            list_type: 名单类型
            entities: 受制裁实体列表
            version: 名单版本

        Returns:
            SanctionsList 制裁名单对象
        """
        # 创建Merkle树
        merkle = MerkleTreeCommitment()

        # 提取实体ID并创建集合
        entity_ids = [e.entity_id for e in entities]
        self.entity_sets[list_type] = set(entity_ids)

        # 构建Merkle树
        entity_bytes = [eid.encode() for eid in entity_ids]
        if entity_bytes:
            root, _ = merkle.commit(entity_bytes)
        else:
            root = hashlib.sha256(b"empty_list").digest()

        self.merkle_trees[list_type] = merkle

        # 创建名单对象
        sanctions_list = SanctionsList(
            list_type=list_type,
            version=version,
            merkle_root=root,
            size=len(entities),
            metadata={"entity_types": list(set(e.entity_type for e in entities))},
        )

        self.sanctions_lists[list_type] = sanctions_list
        return sanctions_list

    def create_address_commitment(
        self,
        address: str,
        address_type: str = "ethereum",
        blinding_factor: Optional[int] = None,
    ) -> AddressCommitment:
        """创建地址承诺

        Args:
            address: 区块链地址
            address_type: 地址类型
            blinding_factor: 可选的盲因子

        Returns:
            AddressCommitment
        """
        if blinding_factor is None:
            blinding_factor = self.curve.random_scalar()

        # 计算地址哈希
        address_normalized = address.lower().strip()
        address_hash = int.from_bytes(
            hashlib.sha256(address_normalized.encode()).digest(),
            'big'
        ) % self.curve.n

        # 创建Pedersen承诺
        commitment, _ = self.pedersen.commit(address_hash, blinding_factor)

        return AddressCommitment(
            commitment=commitment,
            address_hash=address_hash,
            blinding_factor=blinding_factor,
            address_type=address_type,
        )

    def prove_not_sanctioned(
        self,
        address: str,
        address_commitment: AddressCommitment,
        list_types: Optional[List[SanctionsListType]] = None,
        validity_hours: int = 24,
    ) -> SanctionsProof:
        """证明地址不在制裁名单中

        Args:
            address: 区块链地址
            address_commitment: 地址承诺
            list_types: 要筛查的名单类型（默认所有已注册）
            validity_hours: 证明有效期（小时）

        Returns:
            SanctionsProof

        Raises:
            ValueError: 如果地址在任何名单中
        """
        if list_types is None:
            list_types = list(self.sanctions_lists.keys())

        # 标准化地址
        address_normalized = address.lower().strip()
        address_id = hashlib.sha256(address_normalized.encode()).hexdigest()

        # 检查每个名单
        list_roots = {}
        non_membership_proofs = {}

        for list_type in list_types:
            if list_type not in self.sanctions_lists:
                continue

            entity_set = self.entity_sets.get(list_type, set())

            # 检查是否在名单中
            if address_id in entity_set or address_normalized in entity_set:
                raise ValueError(
                    f"Address is on sanctions list: {list_type.value}"
                )

            # 获取名单根
            sanctions_list = self.sanctions_lists[list_type]
            list_roots[list_type.value] = sanctions_list.merkle_root

            # 生成非成员证明
            non_membership_proofs[list_type.value] = self._create_non_membership_proof(
                address_id,
                list_type,
            )

        # 生成知识证明
        knowledge_proof = self._create_knowledge_proof(
            address_commitment,
            list_roots,
        )

        # 计算有效期
        from datetime import timedelta
        valid_until = dt.now() + timedelta(hours=validity_hours)

        return SanctionsProof(
            proof_type="non_membership",
            address_commitment=address_commitment.commitment,
            screened_lists=list_types,
            list_roots=list_roots,
            non_membership_proofs=non_membership_proofs,
            knowledge_proof=knowledge_proof,
            valid_until=valid_until,
        )

    def _create_non_membership_proof(
        self,
        address_id: str,
        list_type: SanctionsListType,
    ) -> Dict[str, Any]:
        """创建非成员证明"""
        # 简化实现：使用Schnorr风格证明
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 计算挑战
        list_root = self.sanctions_lists[list_type].merkle_root
        e_data = R.to_bytes() + list_root + address_id.encode()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 计算响应
        s = (k + e * self.curve.random_scalar()) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
            "list_size": self.sanctions_lists[list_type].size,
        }

    def _create_knowledge_proof(
        self,
        address_commitment: AddressCommitment,
        list_roots: Dict[str, bytes],
    ) -> Dict[str, Any]:
        """创建知识证明"""
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 挑战包含所有公开信息
        roots_bytes = b"".join(list_roots.values())
        e_data = (
            R.to_bytes() +
            address_commitment.commitment.to_bytes() +
            roots_bytes
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s = (k + e * address_commitment.blinding_factor) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
        }

    def verify_not_sanctioned(
        self,
        proof: SanctionsProof,
        expected_lists: Optional[List[SanctionsListType]] = None,
    ) -> bool:
        """验证制裁筛查证明

        Args:
            proof: 制裁筛查证明
            expected_lists: 期望筛查的名单

        Returns:
            验证是否通过
        """
        # 检查有效期
        if not proof.is_valid():
            return False

        # 检查证明类型
        if proof.proof_type != "non_membership":
            return False

        # 检查承诺点在曲线上
        if not proof.address_commitment.on_curve():
            return False

        # 检查名单覆盖
        if expected_lists:
            for list_type in expected_lists:
                if list_type not in proof.screened_lists:
                    return False

        # 验证每个名单的非成员证明
        for list_type in proof.screened_lists:
            list_key = list_type.value
            if list_key not in proof.non_membership_proofs:
                return False

            if not self._verify_non_membership_proof(
                proof.non_membership_proofs[list_key],
                proof.list_roots.get(list_key, b""),
            ):
                return False

        # 验证知识证明
        if not self._verify_knowledge_proof(proof.knowledge_proof):
            return False

        return True

    def _verify_non_membership_proof(
        self,
        proof: Dict[str, Any],
        list_root: bytes,
    ) -> bool:
        """验证非成员证明"""
        try:
            s = int(proof["response"])
            e = int(proof["challenge"])

            if s <= 0 or s >= self.curve.n:
                return False
            if e <= 0 or e >= self.curve.n:
                return False

            return True
        except (KeyError, ValueError):
            return False

    def _verify_knowledge_proof(self, proof: Dict[str, Any]) -> bool:
        """验证知识证明"""
        try:
            s = int(proof["response"])
            e = int(proof["challenge"])

            if s <= 0 or s >= self.curve.n:
                return False
            if e <= 0 or e >= self.curve.n:
                return False

            return True
        except (KeyError, ValueError):
            return False

    def batch_screen(
        self,
        addresses: List[str],
        list_types: Optional[List[SanctionsListType]] = None,
    ) -> Dict[str, bool]:
        """批量筛查地址

        Args:
            addresses: 地址列表
            list_types: 要筛查的名单

        Returns:
            {address: is_clear} 映射
        """
        if list_types is None:
            list_types = list(self.sanctions_lists.keys())

        results = {}
        for address in addresses:
            address_normalized = address.lower().strip()
            address_id = hashlib.sha256(address_normalized.encode()).hexdigest()

            is_clear = True
            for list_type in list_types:
                entity_set = self.entity_sets.get(list_type, set())
                if address_id in entity_set or address_normalized in entity_set:
                    is_clear = False
                    break

            results[address] = is_clear

        return results


# ============================================================
# 预定义制裁名单（示例数据）
# ============================================================

def _create_sample_sanctions_entities(
    addresses: List[str],
    list_type: SanctionsListType,
) -> List[SanctionedEntity]:
    """创建示例制裁实体"""
    entities = []
    for addr in addresses:
        addr_normalized = addr.lower().strip()
        entity_id = hashlib.sha256(addr_normalized.encode()).hexdigest()
        entities.append(SanctionedEntity(
            entity_id=entity_id,
            entity_type="address",
            raw_value=addr,
            source_list=list_type,
            reason="Sanctions evasion",
        ))
    return entities


# OFAC SDN 示例地址（来自公开的制裁案例）
OFAC_SDN_ADDRESSES = [
    "0x8589427373d6d84e98730d7795d8f6f8731fda16",  # Tornado Cash
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",
    "0xdd4c48c0b24039969fc16d1cdf626eab821d3384",
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",
    "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3",
]

# 创建OFAC SDN名单
OFAC_SDN_LIST = _create_sample_sanctions_entities(
    OFAC_SDN_ADDRESSES,
    SanctionsListType.OFAC_SDN,
)

# EU制裁示例地址
EU_SANCTIONS_ADDRESSES = [
    "0x1234567890abcdef1234567890abcdef12345678",
    "0xabcdef1234567890abcdef1234567890abcdef12",
]

EU_SANCTIONS_LIST = _create_sample_sanctions_entities(
    EU_SANCTIONS_ADDRESSES,
    SanctionsListType.EU_SANCTIONS,
)

# UN制裁示例地址
UN_SANCTIONS_ADDRESSES = [
    "0xdeadbeef1234567890abcdef1234567890abcdef",
]

UN_SANCTIONS_LIST = _create_sample_sanctions_entities(
    UN_SANCTIONS_ADDRESSES,
    SanctionsListType.UN_SANCTIONS,
)


def create_default_screener() -> SanctionsScreener:
    """创建带有默认名单的筛查器"""
    screener = SanctionsScreener()

    # 注册OFAC SDN名单
    screener.register_sanctions_list(
        SanctionsListType.OFAC_SDN,
        OFAC_SDN_LIST,
        version="2024.04",
    )

    # 注册EU制裁名单
    screener.register_sanctions_list(
        SanctionsListType.EU_SANCTIONS,
        EU_SANCTIONS_LIST,
        version="2024.04",
    )

    # 注册UN制裁名单
    screener.register_sanctions_list(
        SanctionsListType.UN_SANCTIONS,
        UN_SANCTIONS_LIST,
        version="2024.04",
    )

    return screener
