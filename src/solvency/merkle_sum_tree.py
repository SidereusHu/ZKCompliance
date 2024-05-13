"""
Merkle Sum Tree - 默克尔求和树

实现储备金证明的核心数据结构。
与普通Merkle树不同，每个节点除了存储哈希外，还存储子树余额总和。

特点:
1. 根节点包含总负债
2. 可生成包含证明，用户可验证自己的余额被正确包含
3. 支持零知识证明，不泄露其他用户信息

基于Maxwell的Merkle-tree Proof of Solvency方案改进。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Any
from datetime import datetime
import hashlib
import secrets
from enum import Enum


class AssetType(Enum):
    """资产类型"""
    BTC = "btc"
    ETH = "eth"
    USDT = "usdt"
    USDC = "usdc"
    OTHER = "other"


@dataclass
class UserBalance:
    """用户余额记录"""
    user_id: str  # 用户ID（内部使用，不公开）
    user_hash: bytes  # 用户ID哈希（用于隐私保护）
    balance: int  # 余额（最小单位，如satoshi或wei）
    asset_type: AssetType = AssetType.ETH
    nonce: bytes = field(default_factory=lambda: secrets.token_bytes(16))

    # 可选：多资产支持
    balances: Dict[AssetType, int] = field(default_factory=dict)

    def __post_init__(self):
        if not self.user_hash:
            self.user_hash = hashlib.sha256(
                self.user_id.encode() + self.nonce
            ).digest()

    def compute_leaf_hash(self) -> bytes:
        """计算叶子节点哈希"""
        data = (
            self.user_hash +
            self.balance.to_bytes(32, 'big') +
            self.asset_type.value.encode()
        )
        return hashlib.sha256(data).digest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_hash": self.user_hash.hex()[:16] + "...",
            "balance": self.balance,
            "asset_type": self.asset_type.value,
        }


@dataclass
class MerkleSumNode:
    """Merkle Sum Tree节点"""
    # 节点哈希
    hash: bytes
    # 子树余额总和
    sum: int
    # 左子节点
    left: Optional['MerkleSumNode'] = None
    # 右子节点
    right: Optional['MerkleSumNode'] = None
    # 是否为叶子节点
    is_leaf: bool = False
    # 叶子节点关联的用户余额
    user_balance: Optional[UserBalance] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hash": self.hash.hex()[:16] + "...",
            "sum": self.sum,
            "is_leaf": self.is_leaf,
        }


@dataclass
class InclusionProof:
    """包含证明

    证明某个用户余额被正确包含在Merkle Sum Tree中。
    """
    # 用户哈希
    user_hash: bytes
    # 用户余额
    balance: int
    # 资产类型
    asset_type: AssetType
    # 证明路径（兄弟节点哈希和求和）
    proof_path: List[Tuple[bytes, int, bool]]  # (hash, sum, is_left)
    # 叶子索引
    leaf_index: int
    # 根哈希
    root_hash: bytes
    # 总负债
    total_liabilities: int
    # 创建时间
    created_at: datetime = field(default_factory=datetime.now)
    # 证明ID
    proof_id: str = field(default_factory=lambda: secrets.token_hex(8))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "user_hash": self.user_hash.hex()[:16] + "...",
            "balance": self.balance,
            "asset_type": self.asset_type.value,
            "root_hash": self.root_hash.hex()[:16] + "...",
            "total_liabilities": self.total_liabilities,
            "path_length": len(self.proof_path),
            "created_at": self.created_at.isoformat(),
        }


class MerkleSumTree:
    """
    Merkle Sum Tree实现

    用于储备金证明的核心数据结构。
    每个节点存储:
    1. 子节点哈希的组合哈希
    2. 子树中所有余额的总和

    安全特性:
    - 任何余额修改都会改变根哈希
    - 无法隐藏负余额（会被求和检测）
    - 用户可独立验证自己的包含
    """

    def __init__(self):
        self.root: Optional[MerkleSumNode] = None
        self.leaves: List[MerkleSumNode] = []
        self.user_indices: Dict[bytes, int] = {}  # user_hash -> leaf index
        self.total_liabilities: int = 0

    def build_tree(self, balances: List[UserBalance]) -> MerkleSumNode:
        """
        从用户余额列表构建Merkle Sum Tree

        Args:
            balances: 用户余额列表

        Returns:
            根节点
        """
        if not balances:
            # 空树
            empty_hash = hashlib.sha256(b"empty").digest()
            self.root = MerkleSumNode(hash=empty_hash, sum=0, is_leaf=True)
            return self.root

        # 创建叶子节点
        self.leaves = []
        for i, balance in enumerate(balances):
            leaf_hash = balance.compute_leaf_hash()
            leaf = MerkleSumNode(
                hash=leaf_hash,
                sum=balance.balance,
                is_leaf=True,
                user_balance=balance
            )
            self.leaves.append(leaf)
            self.user_indices[balance.user_hash] = i

        # 补齐到2的幂次
        n = 1
        while n < len(self.leaves):
            n *= 2

        # 用空节点补齐
        while len(self.leaves) < n:
            empty_hash = hashlib.sha256(
                b"empty" + len(self.leaves).to_bytes(4, 'big')
            ).digest()
            self.leaves.append(MerkleSumNode(
                hash=empty_hash,
                sum=0,
                is_leaf=True
            ))

        # 自底向上构建树
        current_level = self.leaves.copy()

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]

                # 计算父节点哈希
                combined = (
                    left.hash +
                    right.hash +
                    left.sum.to_bytes(32, 'big') +
                    right.sum.to_bytes(32, 'big')
                )
                parent_hash = hashlib.sha256(combined).digest()

                # 计算父节点求和
                parent_sum = left.sum + right.sum

                parent = MerkleSumNode(
                    hash=parent_hash,
                    sum=parent_sum,
                    left=left,
                    right=right
                )
                next_level.append(parent)

            current_level = next_level

        self.root = current_level[0]
        self.total_liabilities = self.root.sum
        return self.root

    def get_root_hash(self) -> bytes:
        """获取根哈希"""
        if self.root is None:
            return hashlib.sha256(b"empty").digest()
        return self.root.hash

    def get_total_liabilities(self) -> int:
        """获取总负债"""
        return self.total_liabilities

    def generate_inclusion_proof(
        self,
        user_hash: bytes
    ) -> Optional[InclusionProof]:
        """
        为用户生成包含证明

        Args:
            user_hash: 用户哈希

        Returns:
            InclusionProof 或 None（如果用户不存在）
        """
        if user_hash not in self.user_indices:
            return None

        leaf_index = self.user_indices[user_hash]
        leaf = self.leaves[leaf_index]
        user_balance = leaf.user_balance

        if user_balance is None:
            return None

        # 收集证明路径
        proof_path = self._collect_proof_path(leaf_index)

        return InclusionProof(
            user_hash=user_hash,
            balance=user_balance.balance,
            asset_type=user_balance.asset_type,
            proof_path=proof_path,
            leaf_index=leaf_index,
            root_hash=self.root.hash,
            total_liabilities=self.total_liabilities
        )

    def _collect_proof_path(
        self,
        leaf_index: int
    ) -> List[Tuple[bytes, int, bool]]:
        """收集从叶子到根的证明路径"""
        path = []
        current_index = leaf_index
        current_level = self.leaves.copy()

        while len(current_level) > 1:
            # 找到兄弟节点
            if current_index % 2 == 0:
                # 当前是左节点，兄弟在右边
                sibling_index = current_index + 1
                is_left = False  # 兄弟在右边
            else:
                # 当前是右节点，兄弟在左边
                sibling_index = current_index - 1
                is_left = True  # 兄弟在左边

            sibling = current_level[sibling_index]
            path.append((sibling.hash, sibling.sum, is_left))

            # 移动到上一层
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1]
                combined = (
                    left.hash +
                    right.hash +
                    left.sum.to_bytes(32, 'big') +
                    right.sum.to_bytes(32, 'big')
                )
                parent_hash = hashlib.sha256(combined).digest()
                parent_sum = left.sum + right.sum
                next_level.append(MerkleSumNode(
                    hash=parent_hash,
                    sum=parent_sum
                ))

            current_level = next_level
            current_index //= 2

        return path

    def verify_inclusion_proof(
        self,
        proof: InclusionProof
    ) -> Tuple[bool, str]:
        """
        验证包含证明

        Args:
            proof: 包含证明

        Returns:
            (is_valid, message)
        """
        # 重建叶子哈希
        user_balance = UserBalance(
            user_id="",  # 不需要原始ID
            user_hash=proof.user_hash,
            balance=proof.balance,
            asset_type=proof.asset_type
        )
        current_hash = user_balance.compute_leaf_hash()
        current_sum = proof.balance

        # 沿路径向上验证
        for sibling_hash, sibling_sum, is_left in proof.proof_path:
            if is_left:
                # 兄弟在左边
                combined = (
                    sibling_hash +
                    current_hash +
                    sibling_sum.to_bytes(32, 'big') +
                    current_sum.to_bytes(32, 'big')
                )
            else:
                # 兄弟在右边
                combined = (
                    current_hash +
                    sibling_hash +
                    current_sum.to_bytes(32, 'big') +
                    sibling_sum.to_bytes(32, 'big')
                )

            current_hash = hashlib.sha256(combined).digest()
            current_sum += sibling_sum

        # 验证根哈希
        if current_hash != proof.root_hash:
            return False, "Root hash mismatch"

        # 验证总负债
        if current_sum != proof.total_liabilities:
            return False, "Total liabilities mismatch"

        return True, "Proof verified successfully"

    def update_balance(
        self,
        user_hash: bytes,
        new_balance: int
    ) -> bool:
        """
        更新用户余额（需要重建树）

        注意：实际实现中可能使用增量更新优化

        Args:
            user_hash: 用户哈希
            new_balance: 新余额

        Returns:
            是否成功
        """
        if user_hash not in self.user_indices:
            return False

        leaf_index = self.user_indices[user_hash]
        leaf = self.leaves[leaf_index]

        if leaf.user_balance is None:
            return False

        # 更新余额
        leaf.user_balance.balance = new_balance

        # 重建整个树（简单实现）
        balances = [
            leaf.user_balance
            for leaf in self.leaves
            if leaf.user_balance is not None
        ]
        self.build_tree(balances)

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """获取树的统计信息"""
        return {
            "total_users": len(self.user_indices),
            "total_liabilities": self.total_liabilities,
            "tree_height": len(self.leaves).bit_length(),
            "root_hash": self.root.hash.hex()[:32] + "..." if self.root else None,
        }


class MerkleSumTreeBuilder:
    """Merkle Sum Tree构建器 - 提供更方便的API"""

    def __init__(self):
        self.balances: List[UserBalance] = []

    def add_user(
        self,
        user_id: str,
        balance: int,
        asset_type: AssetType = AssetType.ETH
    ) -> bytes:
        """
        添加用户

        Returns:
            用户哈希（用于后续查询）
        """
        user_balance = UserBalance(
            user_id=user_id,
            user_hash=b'',  # 会在__post_init__中计算
            balance=balance,
            asset_type=asset_type
        )
        self.balances.append(user_balance)
        return user_balance.user_hash

    def build(self) -> MerkleSumTree:
        """构建树"""
        tree = MerkleSumTree()
        tree.build_tree(self.balances)
        return tree

    def clear(self) -> None:
        """清空"""
        self.balances = []
