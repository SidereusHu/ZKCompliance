"""
承诺方案

实现零知识证明中常用的承诺方案:
- Pedersen承诺 (加法同态)
- 哈希承诺 (基于SHA256)
- 向量承诺 (Pedersen向量承诺)
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple, Any
from abc import ABC, abstractmethod
import hashlib
import secrets

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    FieldElement,
    BN128,
)


class CommitmentScheme(ABC):
    """承诺方案抽象基类

    承诺方案必须满足两个属性:
    1. 隐藏性 (Hiding): 承诺不泄露原始值
    2. 绑定性 (Binding): 无法为同一承诺找到不同的打开值
    """

    @abstractmethod
    def commit(self, value: Any, randomness: Optional[Any] = None) -> Tuple[Any, Any]:
        """生成承诺

        Args:
            value: 要承诺的值
            randomness: 随机数（可选，不提供则自动生成）

        Returns:
            (commitment, randomness): 承诺值和随机数
        """
        pass

    @abstractmethod
    def verify(self, commitment: Any, value: Any, randomness: Any) -> bool:
        """验证承诺

        Args:
            commitment: 承诺值
            value: 声称的原始值
            randomness: 随机数

        Returns:
            验证是否通过
        """
        pass


@dataclass
class PedersenParams:
    """Pedersen承诺参数"""
    curve: EllipticCurve
    g: Point  # 基点 G
    h: Point  # 另一个基点 H (必须使得 log_G(H) 未知)


class PedersenCommitment(CommitmentScheme):
    """Pedersen承诺

    C = v*G + r*H

    其中:
    - v: 承诺的值
    - r: 随机盲因子
    - G, H: 椭圆曲线上的两个独立基点

    特性:
    - 完美隐藏: 任意承诺值对应无限多个(v, r)对
    - 计算绑定: 基于离散对数困难假设
    - 加法同态: C(v1) + C(v2) = C(v1 + v2)
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.g = self.curve.generator
        # H = hash_to_curve("Pedersen_H")
        self.h = self.curve.hash_to_curve(b"Pedersen_H_generator")

    def commit(
        self,
        value: int,
        randomness: Optional[int] = None
    ) -> Tuple[Point, int]:
        """生成Pedersen承诺

        C = v*G + r*H

        Args:
            value: 要承诺的整数值
            randomness: 盲因子（可选）

        Returns:
            (commitment_point, randomness)
        """
        if randomness is None:
            randomness = self.curve.random_scalar()

        # C = v*G + r*H
        commitment = (value * self.g) + (randomness * self.h)
        return commitment, randomness

    def verify(
        self,
        commitment: Point,
        value: int,
        randomness: int
    ) -> bool:
        """验证Pedersen承诺"""
        expected = (value * self.g) + (randomness * self.h)
        return commitment == expected

    def add_commitments(
        self,
        c1: Point,
        c2: Point
    ) -> Point:
        """加法同态: C(v1) + C(v2)

        如果 C1 = v1*G + r1*H 且 C2 = v2*G + r2*H
        则 C1 + C2 = (v1+v2)*G + (r1+r2)*H = C(v1+v2, r1+r2)
        """
        return c1 + c2

    def scalar_mul_commitment(
        self,
        c: Point,
        scalar: int
    ) -> Point:
        """标量乘法: k * C(v) = C(k*v)"""
        return scalar * c

    def commit_sum(
        self,
        values: List[int],
        randomnesses: Optional[List[int]] = None
    ) -> Tuple[Point, List[int]]:
        """批量承诺并返回总和的承诺

        Returns:
            (sum_commitment, randomnesses)
        """
        if randomnesses is None:
            randomnesses = [self.curve.random_scalar() for _ in values]

        total_commitment = self.curve.infinity()
        for v, r in zip(values, randomnesses):
            c, _ = self.commit(v, r)
            total_commitment = total_commitment + c

        return total_commitment, randomnesses

    def verify_sum(
        self,
        sum_commitment: Point,
        values: List[int],
        randomnesses: List[int]
    ) -> bool:
        """验证总和承诺"""
        total_value = sum(values) % self.curve.n
        total_randomness = sum(randomnesses) % self.curve.n
        return self.verify(sum_commitment, total_value, total_randomness)


class HashCommitment(CommitmentScheme):
    """基于哈希的承诺

    C = H(v || r)

    其中:
    - H: 密码学哈希函数 (SHA-256)
    - v: 承诺的值
    - r: 随机盲因子

    特性:
    - 计算隐藏: 基于哈希函数单向性
    - 计算绑定: 基于哈希函数抗碰撞性
    - 不具有同态性
    """

    def __init__(self, hash_func: str = "sha256"):
        self.hash_func = hash_func

    def _hash(self, data: bytes) -> bytes:
        """计算哈希"""
        if self.hash_func == "sha256":
            return hashlib.sha256(data).digest()
        elif self.hash_func == "sha3_256":
            return hashlib.sha3_256(data).digest()
        else:
            raise ValueError(f"Unsupported hash function: {self.hash_func}")

    def commit(
        self,
        value: bytes,
        randomness: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """生成哈希承诺

        Args:
            value: 要承诺的字节串
            randomness: 随机数（32字节）

        Returns:
            (commitment_hash, randomness)
        """
        if randomness is None:
            randomness = secrets.token_bytes(32)

        # C = H(r || v)  注意顺序：先r后v，防止长度扩展攻击
        commitment = self._hash(randomness + value)
        return commitment, randomness

    def verify(
        self,
        commitment: bytes,
        value: bytes,
        randomness: bytes
    ) -> bool:
        """验证哈希承诺"""
        expected = self._hash(randomness + value)
        return commitment == expected

    def commit_integer(
        self,
        value: int,
        randomness: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """承诺整数值"""
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        return self.commit(value_bytes, randomness)

    def verify_integer(
        self,
        commitment: bytes,
        value: int,
        randomness: bytes
    ) -> bool:
        """验证整数承诺"""
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        return self.verify(commitment, value_bytes, randomness)


class VectorCommitment(CommitmentScheme):
    """向量Pedersen承诺

    C = v1*G1 + v2*G2 + ... + vn*Gn + r*H

    其中:
    - [v1, v2, ..., vn]: 向量元素
    - [G1, G2, ..., Gn]: 独立基点
    - r: 随机盲因子
    - H: 盲化基点

    用于:
    - 内积证明 (Bulletproofs)
    - 批量值承诺
    """

    def __init__(self, size: int, curve: Optional[EllipticCurve] = None):
        """
        Args:
            size: 向量长度
            curve: 使用的椭圆曲线
        """
        self.size = size
        self.curve = curve or BN128

        # 生成独立基点 G1, G2, ..., Gn
        self.g_bases = [
            self.curve.hash_to_curve(f"VectorCommitment_G_{i}".encode())
            for i in range(size)
        ]

        # 盲化基点 H
        self.h = self.curve.hash_to_curve(b"VectorCommitment_H")

    def commit(
        self,
        values: List[int],
        randomness: Optional[int] = None
    ) -> Tuple[Point, int]:
        """生成向量承诺

        Args:
            values: 整数向量
            randomness: 盲因子

        Returns:
            (commitment_point, randomness)
        """
        if len(values) != self.size:
            raise ValueError(f"Expected {self.size} values, got {len(values)}")

        if randomness is None:
            randomness = self.curve.random_scalar()

        # C = sum(vi * Gi) + r * H
        commitment = randomness * self.h
        for v, g in zip(values, self.g_bases):
            commitment = commitment + (v * g)

        return commitment, randomness

    def verify(
        self,
        commitment: Point,
        values: List[int],
        randomness: int
    ) -> bool:
        """验证向量承诺"""
        expected, _ = self.commit(values, randomness)
        return commitment == expected

    def inner_product(
        self,
        a: List[int],
        b: List[int]
    ) -> int:
        """计算内积 <a, b> = sum(ai * bi)"""
        return sum(ai * bi for ai, bi in zip(a, b)) % self.curve.n


@dataclass
class RangeProofParams:
    """范围证明参数"""
    n_bits: int  # 范围的位数
    curve: EllipticCurve
    g: Point
    h: Point


class SimpleRangeCommitment:
    """简化的范围承诺

    证明承诺值在 [0, 2^n) 范围内。

    思路: 将值分解为位，对每一位做承诺
    v = b0 + 2*b1 + 4*b2 + ... + 2^(n-1)*b(n-1)

    每个 bi ∈ {0, 1}
    """

    def __init__(
        self,
        n_bits: int = 64,
        curve: Optional[EllipticCurve] = None
    ):
        self.n_bits = n_bits
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def commit_with_range_proof(
        self,
        value: int
    ) -> Tuple[Point, int, List[Tuple[Point, int]]]:
        """生成值承诺及范围证明

        Args:
            value: 要承诺的值 (必须在 [0, 2^n_bits) 内)

        Returns:
            (value_commitment, value_randomness, bit_commitments)
        """
        if value < 0 or value >= (1 << self.n_bits):
            raise ValueError(f"Value {value} out of range [0, {1 << self.n_bits})")

        # 分解为位
        bits = [(value >> i) & 1 for i in range(self.n_bits)]

        # 对每一位生成承诺
        bit_commitments = []
        total_randomness = 0

        for i, bit in enumerate(bits):
            c, r = self.pedersen.commit(bit)
            bit_commitments.append((c, r))
            # 累计随机数，考虑位权重 2^i
            total_randomness = (total_randomness + r * (1 << i)) % self.curve.n

        # 值承诺 = sum(2^i * C(bi))
        value_commitment = self.curve.infinity()
        for i, (c, _) in enumerate(bit_commitments):
            value_commitment = value_commitment + ((1 << i) * c)

        return value_commitment, total_randomness, bit_commitments

    def verify_range_proof(
        self,
        value_commitment: Point,
        bit_commitments: List[Tuple[Point, int]]
    ) -> bool:
        """验证范围证明

        验证:
        1. 每个位承诺确实承诺了0或1
        2. 位承诺的加权和等于值承诺

        注意: 这是简化版本，完整版本需要额外的零知识证明
        """
        # 重新计算值承诺
        computed_commitment = self.curve.infinity()
        for i, (c, _) in enumerate(bit_commitments):
            computed_commitment = computed_commitment + ((1 << i) * c)

        return computed_commitment == value_commitment


class MerkleTreeCommitment:
    """Merkle树承诺

    用于承诺一组值，支持高效的成员证明。
    """

    def __init__(self, hash_func: str = "sha256"):
        self.hash_func = hash_func
        self._leaves: List[bytes] = []
        self._tree: List[List[bytes]] = []

    def _hash(self, data: bytes) -> bytes:
        """计算哈希"""
        return hashlib.sha256(data).digest()

    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        """哈希一对节点"""
        return self._hash(left + right)

    def commit(
        self,
        values: List[bytes],
        randomness: Optional[List[bytes]] = None
    ) -> Tuple[bytes, List[bytes]]:
        """构建Merkle树并返回根

        Args:
            values: 要承诺的值列表
            randomness: 每个值的随机数（可选）

        Returns:
            (root_hash, randomnesses)
        """
        n = len(values)
        if n == 0:
            raise ValueError("Cannot commit to empty list")

        # 生成随机数
        if randomness is None:
            randomness = [secrets.token_bytes(32) for _ in values]

        # 计算叶子节点 H(r || v)
        self._leaves = [
            self._hash(r + v) for r, v in zip(randomness, values)
        ]

        # 构建树
        self._tree = [self._leaves[:]]
        current_level = self._leaves[:]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self._hash_pair(left, right))
            self._tree.append(next_level)
            current_level = next_level

        root = current_level[0]
        return root, randomness

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """获取成员证明

        Args:
            index: 叶子节点索引

        Returns:
            证明路径 [(sibling_hash, is_left), ...]
        """
        proof = []
        idx = index

        for level in self._tree[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                is_left = False
            else:
                sibling_idx = idx - 1
                is_left = True

            if sibling_idx < len(level):
                proof.append((level[sibling_idx], is_left))
            else:
                proof.append((level[idx], is_left))

            idx = idx // 2

        return proof

    def verify(
        self,
        root: bytes,
        value: bytes,
        randomness: bytes,
        index: int,
        proof: List[Tuple[bytes, bool]]
    ) -> bool:
        """验证成员证明"""
        leaf = self._hash(randomness + value)
        current = leaf

        for sibling, is_left in proof:
            if is_left:
                current = self._hash_pair(sibling, current)
            else:
                current = self._hash_pair(current, sibling)

        return current == root

    @property
    def root(self) -> Optional[bytes]:
        """返回Merkle根"""
        if self._tree:
            return self._tree[-1][0]
        return None
