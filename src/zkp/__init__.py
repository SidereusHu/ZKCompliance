"""
ZK Primitives Module

Phase 1: 零知识证明基础库

提供:
- 有限域运算
- 椭圆曲线操作
- 承诺方案
- 电路抽象
- 证明系统接口
"""

from src.zkp.primitives import (
    FiniteField,
    FieldElement,
    EllipticCurve,
    Point,
    BN128,
    BLS12_381,
)
from src.zkp.commitment import (
    PedersenCommitment,
    HashCommitment,
    VectorCommitment,
    CommitmentScheme,
)
from src.zkp.circuit import (
    Wire,
    Gate,
    GateType,
    R1CSConstraint,
    Circuit,
    CircuitBuilder,
)
from src.zkp.prover import (
    Witness,
    Proof,
    Prover,
    Groth16Prover,
)
from src.zkp.verifier import (
    VerificationKey,
    Verifier,
    Groth16Verifier,
)

__all__ = [
    # Primitives
    "FiniteField",
    "FieldElement",
    "EllipticCurve",
    "Point",
    "BN128",
    "BLS12_381",
    # Commitment
    "PedersenCommitment",
    "HashCommitment",
    "VectorCommitment",
    "CommitmentScheme",
    # Circuit
    "Wire",
    "Gate",
    "GateType",
    "R1CSConstraint",
    "Circuit",
    "CircuitBuilder",
    # Prover
    "Witness",
    "Proof",
    "Prover",
    "Groth16Prover",
    # Verifier
    "VerificationKey",
    "Verifier",
    "Groth16Verifier",
]
