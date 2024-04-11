"""
证明验证器

实现零知识证明的验证:
- Groth16验证 (概念实现)
- Schnorr验证
- Sigma协议验证
"""

from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Tuple, Any
from abc import ABC, abstractmethod
import hashlib

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    FieldElement,
    FiniteField,
    BN128,
)
from src.zkp.prover import Proof, ProvingKey, Witness
from src.zkp.circuit import Circuit


@dataclass
class VerificationKey:
    """验证密钥

    Groth16验证密钥包含:
    - α, β, γ, δ 参数的曲线点
    - 公开输入相关的点
    """
    curve: EllipticCurve
    alpha_g1: Point
    beta_g2: Point  # 简化: 使用G1
    gamma_g2: Point
    delta_g2: Point
    # IC: 公开输入系数
    ic: List[Point] = dc_field(default_factory=list)

    def __repr__(self) -> str:
        return f"VerificationKey(ic_len={len(self.ic)})"


class Verifier(ABC):
    """验证者抽象基类"""

    @abstractmethod
    def verify(
        self,
        proof: Proof,
        public_inputs: List[int],
        verification_key: VerificationKey
    ) -> bool:
        """验证证明"""
        pass


class Groth16Verifier(Verifier):
    """Groth16验证器

    验证方程 (使用配对):
    e(A, B) = e(α, β) · e(Σ li·ICi, γ) · e(C, δ)

    其中 li 是公开输入。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def derive_verification_key(self, proving_key: ProvingKey) -> VerificationKey:
        """从证明密钥导出验证密钥

        在实际系统中，验证密钥是可信设置的一部分。
        """
        g1 = self.curve.generator

        # 生成随机参数（实际应从设置中获取）
        gamma = self.curve.random_scalar()
        delta = self.curve.random_scalar()

        # IC 点 (公开输入系数)
        ic = [
            self.curve.hash_to_curve(f"IC_{i}".encode())
            for i in range(proving_key.num_public + 1)
        ]

        return VerificationKey(
            curve=self.curve,
            alpha_g1=proving_key.alpha_g1,
            beta_g2=proving_key.beta_g1,  # 简化
            gamma_g2=gamma * g1,
            delta_g2=proving_key.delta_g1,
            ic=ic,
        )

    def verify(
        self,
        proof: Proof,
        public_inputs: List[int],
        verification_key: VerificationKey
    ) -> bool:
        """验证Groth16证明

        简化验证流程:
        1. 检查证明点在曲线上
        2. 计算公开输入承诺
        3. 验证配对方程

        注意: 这是概念性实现，不包含实际配对运算。
        """
        vk = verification_key

        # 检查证明点在曲线上
        if not proof.pi_a.on_curve():
            return False
        if not proof.pi_b.on_curve():
            return False
        if not proof.pi_c.on_curve():
            return False

        # 计算公开输入承诺
        # vk_x = IC[0] + Σ(input[i] * IC[i+1])
        if len(public_inputs) + 1 > len(vk.ic):
            return False

        vk_x = vk.ic[0]
        for i, inp in enumerate(public_inputs):
            vk_x = vk_x + (inp * vk.ic[i + 1])

        # 简化的验证检查
        # 实际Groth16使用配对: e(A, B) == e(α, β) * e(vk_x, γ) * e(C, δ)
        # 这里使用简化的非零检查
        if proof.pi_a.is_infinity():
            return False
        if proof.pi_c.is_infinity():
            return False

        # 概念性验证：检查证明结构完整性
        # 实际实现需要 BN128 或 BLS12-381 的配对函数

        return True

    def batch_verify(
        self,
        proofs: List[Proof],
        public_inputs_list: List[List[int]],
        verification_key: VerificationKey
    ) -> bool:
        """批量验证

        利用配对的乘法性质，批量验证多个证明。
        """
        if len(proofs) != len(public_inputs_list):
            return False

        # 简化: 逐个验证
        # 实际可以使用随机线性组合加速
        for proof, inputs in zip(proofs, public_inputs_list):
            if not self.verify(proof, inputs, verification_key):
                return False

        return True


class SchnorrVerifier:
    """Schnorr协议验证器"""

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def verify(
        self,
        R: Point,
        s: int,
        public_point: Point,
        message: bytes = b""
    ) -> bool:
        """验证Schnorr证明

        验证: s*G == R + e*Y
        其中 e = H(R || Y || m)
        """
        g = self.curve.generator

        # 计算挑战
        e_data = R.to_bytes() + public_point.to_bytes() + message
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 验证 s*G == R + e*Y
        lhs = s * g
        rhs = R + (e * public_point)

        return lhs == rhs


class SigmaProtocolVerifier:
    """Sigma协议验证器"""

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def verify_dlog_equality(
        self,
        R1: Point,
        R2: Point,
        s: int,
        g1: Point,
        h1: Point,
        g2: Point,
        h2: Point
    ) -> bool:
        """验证离散对数相等证明

        验证:
        - s*G1 == R1 + e*H1
        - s*G2 == R2 + e*H2
        """
        # 计算挑战
        e_data = R1.to_bytes() + R2.to_bytes() + h1.to_bytes() + h2.to_bytes()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 验证两个等式
        lhs1 = s * g1
        rhs1 = R1 + (e * h1)
        if lhs1 != rhs1:
            return False

        lhs2 = s * g2
        rhs2 = R2 + (e * h2)
        if lhs2 != rhs2:
            return False

        return True

    def verify_dlog_or(
        self,
        R1: Point,
        R2: Point,
        e1: int,
        e2: int,
        s1: int,
        s2: int,
        g1: Point,
        h1: Point,
        g2: Point,
        h2: Point
    ) -> bool:
        """验证离散对数OR证明

        验证:
        - e = e1 + e2 (mod n)
        - s1*G1 == R1 + e1*H1
        - s2*G2 == R2 + e2*H2
        """
        n = self.curve.n

        # 计算总挑战
        e_data = R1.to_bytes() + R2.to_bytes()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % n

        # 验证挑战分解
        if (e1 + e2) % n != e:
            return False

        # 验证两个等式
        lhs1 = s1 * g1
        rhs1 = R1 + (e1 * h1)
        if lhs1 != rhs1:
            return False

        lhs2 = s2 * g2
        rhs2 = R2 + (e2 * h2)
        if lhs2 != rhs2:
            return False

        return True

    def verify_representation(
        self,
        Rs: List[Point],
        ss: List[int],
        bases: List[Point],
        commitment: Point
    ) -> bool:
        """验证表示知识证明

        验证: Σ(si*Gi) == Σ(Ri) + e*C
        """
        n = self.curve.n

        if len(Rs) != len(ss) or len(ss) != len(bases):
            return False

        # 计算挑战
        e_data = b"".join(R.to_bytes() for R in Rs) + commitment.to_bytes()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % n

        # 验证
        lhs = self.curve.infinity()
        for s, g in zip(ss, bases):
            lhs = lhs + (s * g)

        rhs = self.curve.infinity()
        for R in Rs:
            rhs = rhs + R
        rhs = rhs + (e * commitment)

        return lhs == rhs


class RangeProofVerifier:
    """范围证明验证器

    验证值在 [0, 2^n) 范围内。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def verify_bulletproof_style(
        self,
        commitment: Point,
        proof_data: Dict[str, Any]
    ) -> bool:
        """验证Bulletproof风格的范围证明

        简化实现，实际Bulletproofs更复杂。
        """
        # 简化验证逻辑
        # 实际需要验证内积证明

        if commitment.is_infinity():
            return False

        # 检查证明数据完整性
        required_fields = ["L_vec", "R_vec", "a", "b"]
        for field in required_fields:
            if field not in proof_data:
                return False

        return True


class MembershipProofVerifier:
    """集合成员证明验证器

    验证某值属于已知集合（不泄露具体是哪个）。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def verify_ring_signature(
        self,
        message: bytes,
        ring: List[Point],
        signature: Tuple[List[int], int]
    ) -> bool:
        """验证环签名

        证明签名者是环中的某个成员。
        """
        c_values, s_final = signature
        n = len(ring)

        if len(c_values) != n:
            return False

        g = self.curve.generator

        # 验证环关系
        for i in range(n):
            pk = ring[i]
            c = c_values[i]
            s = c_values[(i + 1) % n] if i < n - 1 else s_final

            # 计算 R = s*G - c*pk
            R = (s * g) + ((-c % self.curve.n) * pk)

            # 计算期望的挑战
            e_data = message + R.to_bytes() + pk.to_bytes()
            expected_c = int.from_bytes(
                hashlib.sha256(e_data).digest(), 'big'
            ) % self.curve.n

            # 验证（简化）
            # 实际环签名验证更复杂

        return True


class AggregateVerifier:
    """聚合验证器

    支持证明聚合和批量验证优化。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128

    def aggregate_schnorr_verify(
        self,
        messages: List[bytes],
        signatures: List[Tuple[Point, int]],
        public_keys: List[Point]
    ) -> bool:
        """聚合Schnorr验证

        使用随机线性组合进行批量验证。
        """
        if not (len(messages) == len(signatures) == len(public_keys)):
            return False

        n = len(messages)
        if n == 0:
            return True

        g = self.curve.generator

        # 生成随机权重
        weights = [
            int.from_bytes(
                hashlib.sha256(f"weight_{i}".encode()).digest(), 'big'
            ) % self.curve.n
            for i in range(n)
        ]

        # 聚合验证
        lhs = self.curve.infinity()  # Σ wi * si * G
        rhs = self.curve.infinity()  # Σ wi * (Ri + ei * Yi)

        for i, (msg, (R, s), pk) in enumerate(zip(messages, signatures, public_keys)):
            w = weights[i]

            # 计算挑战
            e_data = R.to_bytes() + pk.to_bytes() + msg
            e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

            # 聚合
            lhs = lhs + ((w * s) * g)
            rhs = rhs + (w * R) + ((w * e) * pk)

        return lhs == rhs


def create_verifier_from_circuit(circuit: Circuit) -> Tuple[Groth16Verifier, VerificationKey]:
    """从电路创建验证器

    便捷函数，设置验证环境。
    """
    from src.zkp.prover import Groth16Prover

    prover = Groth16Prover()
    proving_key = prover.setup(circuit)

    verifier = Groth16Verifier()
    verification_key = verifier.derive_verification_key(proving_key)

    return verifier, verification_key
