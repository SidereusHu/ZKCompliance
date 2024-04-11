"""
证明生成器

实现零知识证明的证明生成:
- Groth16证明系统 (概念实现)
- 见证计算
- 证明结构
"""

from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Tuple, Any
from abc import ABC, abstractmethod
import hashlib
import secrets
import time

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    FieldElement,
    FiniteField,
    BN128,
)
from src.zkp.circuit import Circuit, R1CSConstraint


@dataclass
class Witness:
    """见证（私密输入）

    包含电路中所有线路的赋值，用于生成证明。
    """
    # 公开输入
    public_inputs: Dict[int, int] = dc_field(default_factory=dict)

    # 私密输入（见证）
    private_inputs: Dict[int, int] = dc_field(default_factory=dict)

    # 中间变量
    intermediate: Dict[int, int] = dc_field(default_factory=dict)

    def get_assignment(self) -> Dict[int, int]:
        """获取完整的变量赋值"""
        assignment = {}
        assignment.update(self.public_inputs)
        assignment.update(self.private_inputs)
        assignment.update(self.intermediate)
        return assignment

    def set(self, wire_id: int, value: int, is_public: bool = False):
        """设置变量值"""
        if is_public:
            self.public_inputs[wire_id] = value
        else:
            self.private_inputs[wire_id] = value

    def get(self, wire_id: int) -> Optional[int]:
        """获取变量值"""
        if wire_id in self.public_inputs:
            return self.public_inputs[wire_id]
        if wire_id in self.private_inputs:
            return self.private_inputs[wire_id]
        if wire_id in self.intermediate:
            return self.intermediate[wire_id]
        return None


@dataclass
class Proof:
    """零知识证明

    Groth16证明结构:
    - π_A ∈ G1
    - π_B ∈ G2 (这里简化为G1)
    - π_C ∈ G1
    """
    pi_a: Point           # G1点
    pi_b: Point           # 简化: 也是G1点 (实际应为G2)
    pi_c: Point           # G1点

    # 元数据
    proof_type: str = "groth16"
    timestamp: float = dc_field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        """序列化证明"""
        return self.pi_a.to_bytes() + self.pi_b.to_bytes() + self.pi_c.to_bytes()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "pi_a": {
                "x": self.pi_a.x.value if self.pi_a.x else None,
                "y": self.pi_a.y.value if self.pi_a.y else None,
            },
            "pi_b": {
                "x": self.pi_b.x.value if self.pi_b.x else None,
                "y": self.pi_b.y.value if self.pi_b.y else None,
            },
            "pi_c": {
                "x": self.pi_c.x.value if self.pi_c.x else None,
                "y": self.pi_c.y.value if self.pi_c.y else None,
            },
            "type": self.proof_type,
            "timestamp": self.timestamp,
        }


@dataclass
class ProvingKey:
    """证明密钥

    Groth16证明密钥包含:
    - α, β, γ, δ 参数的曲线点
    - 电路相关的评估点
    """
    curve: EllipticCurve
    alpha_g1: Point
    beta_g1: Point
    delta_g1: Point
    # 简化: 省略完整的CRS结构
    num_public: int = 0
    num_private: int = 0

    def __repr__(self) -> str:
        return f"ProvingKey(pub={self.num_public}, priv={self.num_private})"


class Prover(ABC):
    """证明者抽象基类"""

    @abstractmethod
    def setup(self, circuit: Circuit) -> ProvingKey:
        """设置阶段：生成证明密钥"""
        pass

    @abstractmethod
    def prove(
        self,
        circuit: Circuit,
        witness: Witness,
        proving_key: ProvingKey
    ) -> Proof:
        """生成证明"""
        pass


class Groth16Prover(Prover):
    """Groth16证明系统

    这是一个概念性实现，展示Groth16的核心流程。
    实际应用应使用 snarkjs, bellman 等成熟库。

    Groth16特点:
    - 非交互式
    - 简洁证明 (3个曲线点)
    - 需要可信设置
    - 证明生成 O(n) 曲线运算
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def setup(self, circuit: Circuit) -> ProvingKey:
        """可信设置

        实际的Groth16设置需要:
        1. 选择有毒废料 τ, α, β, γ, δ
        2. 计算 CRS (Common Reference String)
        3. 销毁有毒废料

        这里简化为随机生成参数。
        """
        # 随机"有毒废料"（实际应在MPC中安全删除）
        alpha = self.curve.random_scalar()
        beta = self.curve.random_scalar()
        delta = self.curve.random_scalar()

        # 生成密钥点
        g1 = self.curve.generator
        alpha_g1 = alpha * g1
        beta_g1 = beta * g1
        delta_g1 = delta * g1

        constraints, num_vars, num_public, num_private = circuit.to_r1cs()

        return ProvingKey(
            curve=self.curve,
            alpha_g1=alpha_g1,
            beta_g1=beta_g1,
            delta_g1=delta_g1,
            num_public=num_public,
            num_private=num_private,
        )

    def prove(
        self,
        circuit: Circuit,
        witness: Witness,
        proving_key: ProvingKey
    ) -> Proof:
        """生成Groth16证明

        简化流程:
        1. 验证见证满足约束
        2. 计算多项式评估
        3. 计算证明元素

        实际Groth16需要:
        - 计算 A(τ), B(τ), C(τ) 的多项式
        - 使用双线性配对
        """
        # 验证见证
        assignment = witness.get_assignment()
        assignment[circuit.one.wire_id] = 1  # 确保常量1

        if not circuit.verify_witness(assignment):
            raise ValueError("Witness does not satisfy circuit constraints")

        # 简化的证明生成
        # 实际Groth16通过多项式计算证明元素
        g1 = self.curve.generator

        # 模拟证明计算
        # 使用见证和证明密钥的组合
        r = self.curve.random_scalar()
        s = self.curve.random_scalar()

        # π_A = α + Σ(ai * wi) + r*δ
        # 简化: 使用随机组合
        a_scalar = (r + sum(assignment.values())) % self.curve.n
        pi_a = a_scalar * g1

        # π_B = β + Σ(bi * wi) + s*δ
        b_scalar = (s + hash(frozenset(assignment.items()))) % self.curve.n
        pi_b = b_scalar * g1

        # π_C = (Σ(ci * wi) + r*s*δ) / δ
        c_scalar = (r * s + len(circuit._constraints)) % self.curve.n
        pi_c = c_scalar * g1

        return Proof(
            pi_a=pi_a,
            pi_b=pi_b,
            pi_c=pi_c,
            proof_type="groth16_simulated",
        )

    def compute_witness(
        self,
        circuit: Circuit,
        inputs: Dict[str, int]
    ) -> Witness:
        """计算见证

        给定输入，计算电路中所有中间变量的值。
        """
        witness = Witness()
        field = circuit.field

        # 设置常量1
        witness.set(circuit.one.wire_id, 1, is_public=True)

        # 设置公开输入
        for wire in circuit._public_inputs:
            if wire.name in inputs:
                witness.set(wire.wire_id, inputs[wire.name] % field.p, is_public=True)

        # 设置私密输入
        for wire in circuit._private_inputs:
            if wire.name in inputs:
                witness.set(wire.wire_id, inputs[wire.name] % field.p, is_public=False)

        # 计算中间变量（按门的顺序）
        assignment = witness.get_assignment()

        for gate in circuit._gates:
            from src.zkp.circuit import GateType

            if gate.gate_type == GateType.ADD:
                if len(gate.inputs) >= 2:
                    a_val = assignment.get(gate.inputs[0].wire_id, 0)
                    b_val = assignment.get(gate.inputs[1].wire_id, 0)
                    result = (a_val + b_val) % field.p
                    assignment[gate.output.wire_id] = result
                    witness.intermediate[gate.output.wire_id] = result

            elif gate.gate_type == GateType.MUL:
                if len(gate.inputs) >= 2:
                    a_val = assignment.get(gate.inputs[0].wire_id, 0)
                    b_val = assignment.get(gate.inputs[1].wire_id, 0)
                    result = (a_val * b_val) % field.p
                    assignment[gate.output.wire_id] = result
                    witness.intermediate[gate.output.wire_id] = result

            elif gate.gate_type == GateType.CONST:
                if gate.constant is not None:
                    assignment[gate.output.wire_id] = gate.constant % field.p
                    witness.intermediate[gate.output.wire_id] = gate.constant % field.p

        return witness


class SchnorrProver:
    """Schnorr协议证明者

    用于离散对数知识证明:
    证明知道 x 使得 Y = x*G
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def prove(
        self,
        secret: int,
        public_point: Point,
        message: bytes = b""
    ) -> Tuple[Point, int]:
        """生成Schnorr证明

        协议:
        1. Prover选择随机 k, 计算 R = k*G
        2. 计算挑战 e = H(R || Y || m)
        3. 计算响应 s = k + e*x

        Returns:
            (R, s)
        """
        g = self.curve.generator

        # 随机数
        k = self.curve.random_scalar()
        R = k * g

        # 挑战
        e_data = R.to_bytes() + public_point.to_bytes() + message
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s = (k + e * secret) % self.curve.n

        return R, s


class SigmaProtocolProver:
    """Sigma协议通用框架

    三轮协议: Commit -> Challenge -> Response
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def prove_dlog_equality(
        self,
        x: int,
        g1: Point,
        h1: Point,
        g2: Point,
        h2: Point
    ) -> Tuple[Point, Point, int]:
        """证明离散对数相等

        证明: log_g1(h1) = log_g2(h2) = x
        即: h1 = x*g1 且 h2 = x*g2

        Returns:
            (R1, R2, s)
        """
        # Commit
        k = self.curve.random_scalar()
        R1 = k * g1
        R2 = k * g2

        # Challenge (Fiat-Shamir)
        e_data = R1.to_bytes() + R2.to_bytes() + h1.to_bytes() + h2.to_bytes()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # Response
        s = (k + e * x) % self.curve.n

        return R1, R2, s

    def prove_dlog_or(
        self,
        x: int,
        which: int,  # 0 或 1, 表示知道哪个
        g1: Point,
        h1: Point,
        g2: Point,
        h2: Point
    ) -> Tuple[Point, Point, int, int, int, int]:
        """证明离散对数的OR关系

        证明: 知道 x 使得 h1 = x*g1 或 h2 = x*g2
        (不泄露具体知道哪一个)

        Returns:
            (R1, R2, e1, e2, s1, s2)
        """
        n = self.curve.n

        if which == 0:
            # 知道 h1 = x*g1
            # 模拟 h2 的证明
            e2 = self.curve.random_scalar()
            s2 = self.curve.random_scalar()
            R2 = (s2 * g2) + ((-e2 % n) * h2)

            # 真实证明 h1
            k1 = self.curve.random_scalar()
            R1 = k1 * g1

            # 总挑战
            e_data = R1.to_bytes() + R2.to_bytes()
            e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % n

            e1 = (e - e2) % n
            s1 = (k1 + e1 * x) % n

        else:
            # 知道 h2 = x*g2
            # 模拟 h1 的证明
            e1 = self.curve.random_scalar()
            s1 = self.curve.random_scalar()
            R1 = (s1 * g1) + ((-e1 % n) * h1)

            # 真实证明 h2
            k2 = self.curve.random_scalar()
            R2 = k2 * g2

            # 总挑战
            e_data = R1.to_bytes() + R2.to_bytes()
            e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % n

            e2 = (e - e1) % n
            s2 = (k2 + e2 * x) % n

        return R1, R2, e1, e2, s1, s2

    def prove_representation(
        self,
        secrets: List[int],
        bases: List[Point],
        commitment: Point
    ) -> Tuple[List[Point], List[int]]:
        """证明表示知识

        证明知道 x1, x2, ..., xn 使得:
        C = x1*G1 + x2*G2 + ... + xn*Gn

        Returns:
            (Rs, ss)
        """
        n = self.curve.n

        # Commit
        ks = [self.curve.random_scalar() for _ in secrets]
        Rs = [k * g for k, g in zip(ks, bases)]

        # Challenge
        e_data = b"".join(R.to_bytes() for R in Rs) + commitment.to_bytes()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % n

        # Response
        ss = [(k + e * x) % n for k, x in zip(ks, secrets)]

        return Rs, ss
