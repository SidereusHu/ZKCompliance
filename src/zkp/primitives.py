"""
密码学原语

实现零知识证明所需的基础密码学组件:
- 有限域运算 (Finite Field Arithmetic)
- 椭圆曲线操作 (Elliptic Curve Operations)
- 常用曲线参数 (BN128, BLS12-381)
"""

from dataclasses import dataclass
from typing import Optional, Tuple, List, Union
from functools import cached_property
import hashlib
import secrets


class FieldElement:
    """有限域元素

    表示模 p 的有限域 F_p 中的元素，支持加减乘除和幂运算。
    """

    def __init__(self, value: int, field: "FiniteField"):
        self.value = value % field.p
        self.field = field

    def __repr__(self) -> str:
        return f"FieldElement({self.value}, mod {self.field.p})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FieldElement):
            return self.value == other.value and self.field.p == other.field.p
        if isinstance(other, int):
            return self.value == other % self.field.p
        return False

    def __hash__(self) -> int:
        return hash((self.value, self.field.p))

    def __add__(self, other: Union["FieldElement", int]) -> "FieldElement":
        if isinstance(other, int):
            other = FieldElement(other, self.field)
        return FieldElement((self.value + other.value) % self.field.p, self.field)

    def __radd__(self, other: int) -> "FieldElement":
        return self.__add__(other)

    def __sub__(self, other: Union["FieldElement", int]) -> "FieldElement":
        if isinstance(other, int):
            other = FieldElement(other, self.field)
        return FieldElement((self.value - other.value) % self.field.p, self.field)

    def __rsub__(self, other: int) -> "FieldElement":
        return FieldElement(other, self.field).__sub__(self)

    def __mul__(self, other: Union["FieldElement", int]) -> "FieldElement":
        if isinstance(other, int):
            other = FieldElement(other, self.field)
        return FieldElement((self.value * other.value) % self.field.p, self.field)

    def __rmul__(self, other: int) -> "FieldElement":
        return self.__mul__(other)

    def __neg__(self) -> "FieldElement":
        return FieldElement((-self.value) % self.field.p, self.field)

    def __pow__(self, exp: int) -> "FieldElement":
        """快速幂运算"""
        if exp < 0:
            # a^(-n) = (a^(-1))^n
            return self.inverse().__pow__(-exp)
        return FieldElement(pow(self.value, exp, self.field.p), self.field)

    def __truediv__(self, other: Union["FieldElement", int]) -> "FieldElement":
        if isinstance(other, int):
            other = FieldElement(other, self.field)
        return self * other.inverse()

    def inverse(self) -> "FieldElement":
        """计算乘法逆元 (使用费马小定理: a^(-1) = a^(p-2) mod p)"""
        if self.value == 0:
            raise ZeroDivisionError("Cannot invert zero")
        return FieldElement(pow(self.value, self.field.p - 2, self.field.p), self.field)

    def sqrt(self) -> Optional["FieldElement"]:
        """计算平方根 (Tonelli-Shanks算法简化版，仅适用于 p ≡ 3 mod 4)"""
        p = self.field.p
        if p % 4 == 3:
            # 简化情况: sqrt(a) = a^((p+1)/4) mod p
            result = pow(self.value, (p + 1) // 4, p)
            if (result * result) % p == self.value:
                return FieldElement(result, self.field)
            return None
        # 完整Tonelli-Shanks实现（略）
        raise NotImplementedError("Full Tonelli-Shanks not implemented")

    def is_zero(self) -> bool:
        return self.value == 0

    def is_one(self) -> bool:
        return self.value == 1

    def to_bytes(self, length: int = 32) -> bytes:
        """转换为字节"""
        return self.value.to_bytes(length, byteorder='big')

    @classmethod
    def from_bytes(cls, data: bytes, field: "FiniteField") -> "FieldElement":
        """从字节创建"""
        return cls(int.from_bytes(data, byteorder='big'), field)


class FiniteField:
    """有限域 F_p

    定义模素数 p 的有限域，提供元素创建和随机采样。
    """

    def __init__(self, p: int):
        """
        Args:
            p: 域的特征（素数）
        """
        self.p = p

    def __repr__(self) -> str:
        return f"FiniteField(p={self.p})"

    def element(self, value: int) -> FieldElement:
        """创建域元素"""
        return FieldElement(value, self)

    def zero(self) -> FieldElement:
        """零元素"""
        return FieldElement(0, self)

    def one(self) -> FieldElement:
        """单位元素"""
        return FieldElement(1, self)

    def random(self) -> FieldElement:
        """随机采样域元素"""
        return FieldElement(secrets.randbelow(self.p), self)

    def from_hash(self, data: bytes) -> FieldElement:
        """从哈希值创建域元素"""
        h = hashlib.sha256(data).digest()
        value = int.from_bytes(h, byteorder='big') % self.p
        return FieldElement(value, self)


@dataclass
class Point:
    """椭圆曲线上的点

    使用仿射坐标 (x, y)，无穷远点用 x=None, y=None 表示。
    """
    x: Optional[FieldElement]
    y: Optional[FieldElement]
    curve: "EllipticCurve"

    def is_infinity(self) -> bool:
        """是否为无穷远点（单位元）"""
        return self.x is None and self.y is None

    def __repr__(self) -> str:
        if self.is_infinity():
            return "Point(infinity)"
        return f"Point({self.x.value}, {self.y.value})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        if self.is_infinity() and other.is_infinity():
            return True
        if self.is_infinity() or other.is_infinity():
            return False
        return self.x == other.x and self.y == other.y

    def __hash__(self) -> int:
        if self.is_infinity():
            return hash(("infinity", id(self.curve)))
        return hash((self.x.value, self.y.value))

    def __neg__(self) -> "Point":
        """点的逆元: -P = (x, -y)"""
        if self.is_infinity():
            return self
        return Point(self.x, -self.y, self.curve)

    def __add__(self, other: "Point") -> "Point":
        """点加法"""
        return self.curve.add(self, other)

    def __sub__(self, other: "Point") -> "Point":
        """点减法: P - Q = P + (-Q)"""
        return self + (-other)

    def __mul__(self, scalar: int) -> "Point":
        """标量乘法: k * P"""
        return self.curve.scalar_mul(self, scalar)

    def __rmul__(self, scalar: int) -> "Point":
        return self.__mul__(scalar)

    def on_curve(self) -> bool:
        """验证点是否在曲线上"""
        return self.curve.is_on_curve(self)

    def to_bytes(self) -> bytes:
        """序列化为字节（未压缩格式）"""
        if self.is_infinity():
            return b'\x00'
        return b'\x04' + self.x.to_bytes(32) + self.y.to_bytes(32)

    @classmethod
    def from_bytes(cls, data: bytes, curve: "EllipticCurve") -> "Point":
        """从字节反序列化"""
        if data[0] == 0:
            return curve.infinity()
        if data[0] == 4:
            x = FieldElement.from_bytes(data[1:33], curve.field)
            y = FieldElement.from_bytes(data[33:65], curve.field)
            return Point(x, y, curve)
        raise ValueError("Invalid point encoding")


class EllipticCurve:
    """椭圆曲线 (短Weierstrass形式)

    曲线方程: y² = x³ + ax + b (mod p)
    """

    def __init__(
        self,
        name: str,
        p: int,      # 域特征
        a: int,      # 曲线参数 a
        b: int,      # 曲线参数 b
        gx: int,     # 生成元 G 的 x 坐标
        gy: int,     # 生成元 G 的 y 坐标
        n: int,      # 曲线阶（G的阶）
        h: int = 1,  # 余因子
    ):
        self.name = name
        self.field = FiniteField(p)
        self.a = self.field.element(a)
        self.b = self.field.element(b)
        self.n = n  # 曲线阶
        self.h = h  # 余因子

        # 生成元
        self._gx = gx
        self._gy = gy

    def __repr__(self) -> str:
        return f"EllipticCurve({self.name})"

    @cached_property
    def generator(self) -> Point:
        """曲线生成元 G"""
        return Point(
            self.field.element(self._gx),
            self.field.element(self._gy),
            self
        )

    @cached_property
    def scalar_field(self) -> FiniteField:
        """标量域 F_n (用于标量乘法)"""
        return FiniteField(self.n)

    def infinity(self) -> Point:
        """无穷远点（单位元）"""
        return Point(None, None, self)

    def point(self, x: int, y: int) -> Point:
        """创建曲线上的点"""
        p = Point(self.field.element(x), self.field.element(y), self)
        if not self.is_on_curve(p):
            raise ValueError(f"Point ({x}, {y}) is not on curve {self.name}")
        return p

    def is_on_curve(self, p: Point) -> bool:
        """验证点是否在曲线上"""
        if p.is_infinity():
            return True
        # y² = x³ + ax + b
        lhs = p.y * p.y
        rhs = p.x * p.x * p.x + self.a * p.x + self.b
        return lhs == rhs

    def add(self, p1: Point, p2: Point) -> Point:
        """点加法实现

        使用标准公式：
        - P + O = P (O是无穷远点)
        - P + (-P) = O
        - P + P: 使用切线斜率 λ = (3x²+a)/(2y)
        - P + Q: 使用割线斜率 λ = (y2-y1)/(x2-x1)
        """
        if p1.is_infinity():
            return p2
        if p2.is_infinity():
            return p1

        # P + (-P) = O
        if p1.x == p2.x and p1.y == -p2.y:
            return self.infinity()

        # 计算斜率 λ
        if p1.x == p2.x and p1.y == p2.y:
            # 点倍乘: λ = (3x² + a) / (2y)
            if p1.y.is_zero():
                return self.infinity()
            lam = (3 * p1.x * p1.x + self.a) / (2 * p1.y)
        else:
            # 一般加法: λ = (y2 - y1) / (x2 - x1)
            lam = (p2.y - p1.y) / (p2.x - p1.x)

        # 计算结果点
        # x3 = λ² - x1 - x2
        # y3 = λ(x1 - x3) - y1
        x3 = lam * lam - p1.x - p2.x
        y3 = lam * (p1.x - x3) - p1.y

        return Point(x3, y3, self)

    def scalar_mul(self, p: Point, k: int) -> Point:
        """标量乘法 (双倍加算法)

        计算 k * P，使用二进制展开优化。
        """
        if k < 0:
            return self.scalar_mul(-p, -k)
        if k == 0:
            return self.infinity()
        if p.is_infinity():
            return p

        k = k % self.n  # 模阶运算

        result = self.infinity()
        addend = p

        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1

        return result

    def random_point(self) -> Point:
        """生成随机曲线点"""
        k = secrets.randbelow(self.n - 1) + 1
        return k * self.generator

    def random_scalar(self) -> int:
        """生成随机标量"""
        return secrets.randbelow(self.n - 1) + 1

    def hash_to_curve(self, data: bytes) -> Point:
        """将任意数据哈希到曲线上的点

        简化实现：hash-and-pray方法
        """
        counter = 0
        while True:
            h = hashlib.sha256(data + counter.to_bytes(4, 'big')).digest()
            x_int = int.from_bytes(h, 'big') % self.field.p
            x = self.field.element(x_int)

            # y² = x³ + ax + b
            y_squared = x * x * x + self.a * x + self.b
            y = y_squared.sqrt()

            if y is not None:
                # 选择y的"正"值（较小的那个）
                if y.value > self.field.p // 2:
                    y = -y
                return Point(x, y, self)

            counter += 1
            if counter > 1000:
                raise RuntimeError("Failed to hash to curve")


# ============================================================
# 预定义曲线参数
# ============================================================

# BN128 (也称为 alt_bn128)
# 用于以太坊预编译合约，广泛用于zkSNARK
BN128 = EllipticCurve(
    name="BN128",
    # 域特征 p
    p=21888242871839275222246405745257275088696311157297823662689037894645226208583,
    # 曲线参数 y² = x³ + 3
    a=0,
    b=3,
    # 生成元 G
    gx=1,
    gy=2,
    # 曲线阶 n
    n=21888242871839275222246405745257275088548364400416034343698204186575808495617,
    h=1,
)

# BLS12-381
# 更安全的曲线，用于以太坊2.0和Zcash
BLS12_381 = EllipticCurve(
    name="BLS12-381",
    # 域特征 p
    p=0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab,
    # 曲线参数 y² = x³ + 4
    a=0,
    b=4,
    # 生成元 G (BLS12-381 G1)
    gx=0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb,
    gy=0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1,
    # 曲线阶 n
    n=0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001,
    h=0x396c8c005555e1568c00aaab0000aaab,
)


# ============================================================
# 辅助函数
# ============================================================

def generate_keypair(curve: EllipticCurve) -> Tuple[int, Point]:
    """生成密钥对

    Returns:
        (私钥 sk, 公钥 pk = sk * G)
    """
    sk = curve.random_scalar()
    pk = sk * curve.generator
    return sk, pk


def ecdh_shared_secret(
    my_private_key: int,
    their_public_key: Point
) -> Point:
    """ECDH密钥交换

    计算共享密钥: shared = my_sk * their_pk
    """
    return my_private_key * their_public_key


def schnorr_sign(
    message: bytes,
    private_key: int,
    curve: EllipticCurve
) -> Tuple[Point, int]:
    """Schnorr签名

    Returns:
        (R, s) where R = k*G, s = k + e*sk
    """
    # 随机数 k
    k = curve.random_scalar()
    R = k * curve.generator

    # 挑战值 e = H(R || pk || m)
    pk = private_key * curve.generator
    e_data = R.to_bytes() + pk.to_bytes() + message
    e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % curve.n

    # s = k + e * sk
    s = (k + e * private_key) % curve.n

    return R, s


def schnorr_verify(
    message: bytes,
    signature: Tuple[Point, int],
    public_key: Point,
    curve: EllipticCurve
) -> bool:
    """验证Schnorr签名

    验证: s*G == R + e*pk
    """
    R, s = signature

    # 计算挑战值
    e_data = R.to_bytes() + public_key.to_bytes() + message
    e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % curve.n

    # 验证 s*G == R + e*pk
    lhs = s * curve.generator
    rhs = R + (e * public_key)

    return lhs == rhs
