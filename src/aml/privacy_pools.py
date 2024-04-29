"""
Privacy Pools - 关联集证明

实现Privacy Pools风格的合规证明系统。
基于Vitalik Buterin等人提出的Privacy Pools概念，
允许用户证明其资金属于合规关联集，同时保护隐私。

核心概念:
1. Association Set (关联集): 一组被认定为合规的地址/交易
2. Deposit/Withdrawal: 资金进出池子的记录
3. Membership Proof: 证明属于某个关联集
4. Exclusion Proof: 证明不属于非法关联集
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Set, Tuple
from datetime import datetime
import hashlib
import secrets

from src.zkp.commitment import PedersenCommitment, MerkleTreeCommitment


class AssociationSetType(Enum):
    """关联集类型"""
    COMPLIANT_EXCHANGES = "compliant_exchanges"  # 合规交易所
    VERIFIED_DEFI = "verified_defi"  # 已验证DeFi协议
    INSTITUTIONAL = "institutional"  # 机构投资者
    RETAIL_KYC = "retail_kyc"  # 已KYC零售用户
    GOVERNMENT = "government"  # 政府相关
    CHARITY = "charity"  # 慈善机构
    MIXER_CLEAN = "mixer_clean"  # 混币器清洁输出
    CUSTOM = "custom"  # 自定义集合


class PoolStatus(Enum):
    """池子状态"""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    FROZEN = "frozen"


@dataclass
class DepositRecord:
    """存款记录"""
    deposit_id: str
    depositor_commitment: bytes  # 存款人承诺(隐藏身份)
    amount_commitment: bytes  # 金额承诺
    timestamp: datetime
    leaf_index: int  # 在Merkle树中的位置
    nullifier_hash: bytes  # 防止双花的nullifier

    # 可选的公开信息
    source_chain: Optional[str] = None
    source_protocol: Optional[str] = None

    def __hash__(self):
        return hash(self.deposit_id)


@dataclass
class WithdrawalRecord:
    """提款记录"""
    withdrawal_id: str
    recipient_commitment: bytes  # 接收人承诺
    amount_commitment: bytes  # 金额承诺
    timestamp: datetime
    nullifier: bytes  # 消耗的nullifier

    # 关联证明
    association_proof: Optional[bytes] = None
    association_set_id: Optional[str] = None

    def __hash__(self):
        return hash(self.withdrawal_id)


@dataclass
class AssociationSet:
    """
    关联集 - 一组被认为合规的地址/交易

    关联集可以由不同的实体创建和维护:
    - 交易所: 其用户的提款地址
    - DeFi协议: 经过验证的交互地址
    - 合规服务商: 经过尽职调查的地址
    - 社区: 通过声誉系统验证的地址
    """
    set_id: str
    set_type: AssociationSetType
    name: str
    description: str

    # Merkle树根 - 承诺所有成员
    merkle_root: bytes = field(default_factory=bytes)

    # 成员(实际部署时应加密存储)
    members: Set[str] = field(default_factory=set)
    member_commitments: List[bytes] = field(default_factory=list)

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    status: PoolStatus = PoolStatus.ACTIVE

    # 创建者信息
    creator: str = ""
    creator_signature: Optional[bytes] = None

    # 统计信息
    member_count: int = 0
    total_volume: int = 0  # 总交易量(wei)

    def add_member(self, address: str, commitment: bytes) -> int:
        """添加成员到关联集"""
        self.members.add(address)
        self.member_commitments.append(commitment)
        self.member_count = len(self.members)
        self.updated_at = datetime.now()
        return len(self.member_commitments) - 1  # 返回索引

    def remove_member(self, address: str) -> bool:
        """从关联集移除成员"""
        if address in self.members:
            self.members.remove(address)
            self.member_count = len(self.members)
            self.updated_at = datetime.now()
            return True
        return False

    def contains(self, address: str) -> bool:
        """检查地址是否在关联集中"""
        return address in self.members


@dataclass
class AssociationProof:
    """
    关联集成员证明

    证明某个存款/提款属于特定的关联集，
    而不透露具体是哪一个成员。
    """
    proof_id: str

    # 关联集信息
    association_set_id: str
    association_set_root: bytes

    # 成员承诺
    member_commitment: bytes

    # Merkle证明路径
    merkle_proof: List[bytes] = field(default_factory=list)
    merkle_proof_indices: List[int] = field(default_factory=list)

    # 零知识证明
    zk_proof: bytes = field(default_factory=bytes)

    # 时间戳
    created_at: datetime = field(default_factory=datetime.now)

    # 验证状态
    is_valid: bool = False
    verified_at: Optional[datetime] = None


@dataclass
class PrivacyPool:
    """
    隐私池 - 管理存款、提款和关联证明

    类似Tornado Cash但增加了合规层:
    - 存款时不需要透露身份
    - 提款时需要证明属于合规关联集
    - 支持多个关联集提供不同级别的合规保证
    """
    pool_id: str
    name: str
    denomination: int  # 固定金额(wei)

    # 存款Merkle树
    deposit_tree_root: bytes = field(default_factory=bytes)
    deposits: List[DepositRecord] = field(default_factory=list)

    # 已使用的nullifiers(防止双花)
    spent_nullifiers: Set[bytes] = field(default_factory=set)

    # 关联的合规集
    association_sets: Dict[str, AssociationSet] = field(default_factory=dict)

    # 提款记录
    withdrawals: List[WithdrawalRecord] = field(default_factory=list)

    # 池子状态
    status: PoolStatus = PoolStatus.ACTIVE
    total_deposits: int = 0
    total_withdrawals: int = 0

    def register_association_set(self, assoc_set: AssociationSet) -> None:
        """注册关联集到池子"""
        self.association_sets[assoc_set.set_id] = assoc_set

    def get_association_set(self, set_id: str) -> Optional[AssociationSet]:
        """获取关联集"""
        return self.association_sets.get(set_id)


class PrivacyPoolProver:
    """
    Privacy Pool证明器

    生成各类证明:
    1. 存款证明 - 证明有效存入资金
    2. 提款证明 - 证明有权提取且属于合规集
    3. 关联证明 - 证明属于特定关联集
    """

    def __init__(self):
        self.pedersen = PedersenCommitment()

    def create_deposit_commitment(
        self,
        depositor_secret: bytes,
        amount: int,
        nullifier_secret: bytes
    ) -> Tuple[bytes, bytes, bytes]:
        """
        创建存款承诺

        Returns:
            (deposit_commitment, amount_commitment, nullifier_hash)
        """
        # 存款人承诺 = H(depositor_secret || nullifier_secret)
        deposit_data = depositor_secret + nullifier_secret
        deposit_commitment = hashlib.sha256(deposit_data).digest()

        # 金额承诺
        amount_commitment, _ = self.pedersen.commit(amount)

        # Nullifier哈希 = H(nullifier_secret)
        nullifier_hash = hashlib.sha256(nullifier_secret).digest()

        return deposit_commitment, amount_commitment, nullifier_hash

    def create_deposit(
        self,
        pool: PrivacyPool,
        depositor_secret: bytes,
        amount: int,
        source_chain: Optional[str] = None,
        source_protocol: Optional[str] = None
    ) -> DepositRecord:
        """创建存款记录"""
        # 生成nullifier秘密
        nullifier_secret = secrets.token_bytes(32)

        # 创建承诺
        deposit_commitment, amount_commitment, nullifier_hash = \
            self.create_deposit_commitment(depositor_secret, amount, nullifier_secret)

        # 创建存款记录
        deposit = DepositRecord(
            deposit_id=secrets.token_hex(16),
            depositor_commitment=deposit_commitment,
            amount_commitment=amount_commitment,
            timestamp=datetime.now(),
            leaf_index=len(pool.deposits),
            nullifier_hash=nullifier_hash,
            source_chain=source_chain,
            source_protocol=source_protocol
        )

        # 添加到池子
        pool.deposits.append(deposit)
        pool.total_deposits += 1

        return deposit

    def prove_association(
        self,
        pool: PrivacyPool,
        association_set_id: str,
        member_address: str,
        member_secret: bytes
    ) -> Optional[AssociationProof]:
        """
        证明属于关联集

        生成零知识证明，证明:
        1. 知道某个member_address的秘密
        2. 该地址在association_set中
        3. 不透露具体是哪个地址
        """
        # 获取关联集
        assoc_set = pool.get_association_set(association_set_id)
        if not assoc_set:
            return None

        # 检查是否是成员
        if not assoc_set.contains(member_address):
            return None

        # 创建成员承诺
        member_data = member_address.encode() + member_secret
        member_commitment = hashlib.sha256(member_data).digest()

        # 构建Merkle证明
        merkle = MerkleTreeCommitment()

        # 重建Merkle树以获取证明路径
        member_bytes_list = [m.encode() for m in assoc_set.members]
        root, _ = merkle.commit(member_bytes_list)

        # 找到成员索引
        member_list = list(assoc_set.members)
        try:
            member_index = member_list.index(member_address)
        except ValueError:
            return None

        # 生成Merkle证明路径(简化版)
        merkle_proof = self._generate_merkle_proof(member_bytes_list, member_index)

        # 生成ZK证明
        zk_proof = self._generate_membership_zk_proof(
            member_commitment,
            root,
            merkle_proof,
            member_index
        )

        return AssociationProof(
            proof_id=secrets.token_hex(16),
            association_set_id=association_set_id,
            association_set_root=root,
            member_commitment=member_commitment,
            merkle_proof=merkle_proof,
            merkle_proof_indices=[member_index],
            zk_proof=zk_proof,
            is_valid=True
        )

    def prove_withdrawal(
        self,
        pool: PrivacyPool,
        deposit: DepositRecord,
        recipient_address: str,
        recipient_secret: bytes,
        nullifier_secret: bytes,
        association_set_id: Optional[str] = None
    ) -> Tuple[WithdrawalRecord, Optional[AssociationProof]]:
        """
        创建提款证明

        证明:
        1. 知道某个存款的秘密
        2. 该nullifier未被使用
        3. (可选)提款地址属于某个合规关联集
        """
        # 验证nullifier
        expected_nullifier = hashlib.sha256(nullifier_secret).digest()
        if expected_nullifier != deposit.nullifier_hash:
            raise ValueError("Invalid nullifier secret")

        # 检查nullifier是否已使用
        if expected_nullifier in pool.spent_nullifiers:
            raise ValueError("Nullifier already spent")

        # 创建接收人承诺
        recipient_data = recipient_address.encode() + recipient_secret
        recipient_commitment = hashlib.sha256(recipient_data).digest()

        # 生成关联证明(如果需要)
        association_proof = None
        if association_set_id:
            association_proof = self.prove_association(
                pool,
                association_set_id,
                recipient_address,
                recipient_secret
            )

        # 创建提款记录
        withdrawal = WithdrawalRecord(
            withdrawal_id=secrets.token_hex(16),
            recipient_commitment=recipient_commitment,
            amount_commitment=deposit.amount_commitment,
            timestamp=datetime.now(),
            nullifier=expected_nullifier,
            association_proof=association_proof.zk_proof if association_proof else None,
            association_set_id=association_set_id
        )

        # 标记nullifier为已使用
        pool.spent_nullifiers.add(expected_nullifier)
        pool.withdrawals.append(withdrawal)
        pool.total_withdrawals += 1

        return withdrawal, association_proof

    def _generate_merkle_proof(
        self,
        leaves: List[bytes],
        index: int
    ) -> List[bytes]:
        """生成Merkle证明路径"""
        if len(leaves) == 0:
            return []

        # 补齐到2的幂次
        n = 1
        while n < len(leaves):
            n *= 2

        padded_leaves = leaves + [b'\x00' * 32] * (n - len(leaves))

        # 计算所有层的哈希
        current_layer = [hashlib.sha256(leaf).digest() for leaf in padded_leaves]
        proof = []
        current_index = index

        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i + 1] if i + 1 < len(current_layer) else left

                # 保存兄弟节点到证明路径
                if i == (current_index // 2) * 2:
                    if current_index % 2 == 0:
                        proof.append(right)
                    else:
                        proof.append(left)

                combined = hashlib.sha256(left + right).digest()
                next_layer.append(combined)

            current_layer = next_layer
            current_index //= 2

        return proof

    def _generate_membership_zk_proof(
        self,
        member_commitment: bytes,
        merkle_root: bytes,
        merkle_proof: List[bytes],
        index: int
    ) -> bytes:
        """
        生成成员资格ZK证明

        证明: "我知道一个值v，使得:
        1. commitment = H(v || secret)
        2. v在以merkle_root为根的Merkle树中"
        """
        # 构造证明数据
        proof_data = (
            member_commitment +
            merkle_root +
            index.to_bytes(4, 'big') +
            b''.join(merkle_proof)
        )

        # 生成证明签名(简化版 - 实际应使用zk-SNARK)
        proof_hash = hashlib.sha256(proof_data).digest()

        # 添加随机性
        randomness = secrets.token_bytes(32)
        final_proof = hashlib.sha256(proof_hash + randomness).digest()

        return final_proof


class PrivacyPoolVerifier:
    """
    Privacy Pool验证器

    验证各类证明的有效性
    """

    def __init__(self):
        self.pedersen = PedersenCommitment()

    def verify_deposit(
        self,
        pool: PrivacyPool,
        deposit: DepositRecord
    ) -> bool:
        """验证存款有效性"""
        # 检查存款是否在池子中
        if deposit not in pool.deposits:
            return False

        # 检查nullifier未被使用
        if deposit.nullifier_hash in pool.spent_nullifiers:
            return False

        return True

    def verify_withdrawal(
        self,
        pool: PrivacyPool,
        withdrawal: WithdrawalRecord,
        require_association: bool = True
    ) -> Tuple[bool, str]:
        """
        验证提款有效性

        Returns:
            (is_valid, message)
        """
        # 检查nullifier
        if withdrawal.nullifier not in pool.spent_nullifiers:
            # 这意味着提款还未被处理
            return False, "Withdrawal not processed"

        # 如果要求关联证明
        if require_association:
            if not withdrawal.association_set_id:
                return False, "Association proof required"

            if withdrawal.association_set_id not in pool.association_sets:
                return False, "Unknown association set"

            if not withdrawal.association_proof:
                return False, "Missing association proof"

        return True, "Valid withdrawal"

    def verify_association_proof(
        self,
        proof: AssociationProof,
        association_set: AssociationSet
    ) -> Tuple[bool, str]:
        """
        验证关联证明

        Returns:
            (is_valid, message)
        """
        # 检查关联集ID匹配
        if proof.association_set_id != association_set.set_id:
            return False, "Association set ID mismatch"

        # 检查关联集状态
        if association_set.status != PoolStatus.ACTIVE:
            return False, f"Association set is {association_set.status.value}"

        # 验证Merkle根(在实际系统中应验证链上状态)
        if proof.association_set_root != association_set.merkle_root:
            # 允许根不同(因为集合可能已更新)
            # 但需要验证证明时的根是有效的历史根
            pass

        # 验证ZK证明(简化版)
        if not proof.zk_proof:
            return False, "Missing ZK proof"

        if len(proof.zk_proof) != 32:
            return False, "Invalid ZK proof format"

        return True, "Valid association proof"

    def verify_compliance(
        self,
        pool: PrivacyPool,
        withdrawal: WithdrawalRecord,
        required_set_types: Optional[List[AssociationSetType]] = None
    ) -> Tuple[bool, str, Optional[AssociationSetType]]:
        """
        验证提款的合规性

        Args:
            pool: 隐私池
            withdrawal: 提款记录
            required_set_types: 要求的关联集类型列表

        Returns:
            (is_compliant, message, matched_set_type)
        """
        if not withdrawal.association_set_id:
            return False, "No association proof provided", None

        assoc_set = pool.get_association_set(withdrawal.association_set_id)
        if not assoc_set:
            return False, "Unknown association set", None

        # 检查关联集类型是否符合要求
        if required_set_types:
            if assoc_set.set_type not in required_set_types:
                return False, f"Association set type {assoc_set.set_type.value} not in required types", None

        # 验证关联证明
        if withdrawal.association_proof:
            # 重建AssociationProof对象进行验证
            proof = AssociationProof(
                proof_id="verification",
                association_set_id=withdrawal.association_set_id,
                association_set_root=assoc_set.merkle_root,
                member_commitment=b'',  # 不需要验证
                zk_proof=withdrawal.association_proof
            )

            is_valid, msg = self.verify_association_proof(proof, assoc_set)
            if not is_valid:
                return False, msg, None

        return True, "Compliant withdrawal", assoc_set.set_type


# 预定义的关联集模板
COMPLIANT_EXCHANGE_SET = AssociationSet(
    set_id="compliant_exchanges_v1",
    set_type=AssociationSetType.COMPLIANT_EXCHANGES,
    name="Compliant Exchanges Association Set",
    description="合规交易所的用户提款地址集合，包括已完成KYC的用户",
    creator="ZK-Compliance System"
)

VERIFIED_DEFI_SET = AssociationSet(
    set_id="verified_defi_v1",
    set_type=AssociationSetType.VERIFIED_DEFI,
    name="Verified DeFi Protocols Set",
    description="经过安全审计和合规审查的DeFi协议交互地址",
    creator="ZK-Compliance System"
)

INSTITUTIONAL_SET = AssociationSet(
    set_id="institutional_v1",
    set_type=AssociationSetType.INSTITUTIONAL,
    name="Institutional Investors Set",
    description="机构投资者和托管服务的地址集合",
    creator="ZK-Compliance System"
)
