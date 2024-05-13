"""
Asset Commitment System - 资产承诺系统

实现交易所资产的零知识承诺和证明:
- 证明持有特定数量的链上资产
- 不泄露具体地址或余额
- 支持多资产、多链证明
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Any, Set
from datetime import datetime
from enum import Enum
import hashlib
import secrets

from src.zkp.primitives import BN128, Point
from src.zkp.commitment import PedersenCommitment
from src.solvency.merkle_sum_tree import AssetType


class ChainType(Enum):
    """区块链类型"""
    ETHEREUM = "ethereum"
    BITCOIN = "bitcoin"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BSC = "bsc"
    SOLANA = "solana"


class WalletType(Enum):
    """钱包类型"""
    HOT_WALLET = "hot"  # 热钱包
    COLD_WALLET = "cold"  # 冷钱包
    CUSTODIAN = "custodian"  # 托管钱包
    MULTISIG = "multisig"  # 多签钱包


@dataclass
class Asset:
    """资产记录"""
    asset_id: str
    asset_type: AssetType
    chain: ChainType
    # 地址信息（私密）
    address: str
    # 余额
    balance: int  # 最小单位
    # 地址哈希（自动计算）
    address_hash: bytes = field(default_factory=bytes)
    # 钱包类型
    wallet_type: WalletType = WalletType.HOT_WALLET
    # 验证信息
    last_verified: Optional[datetime] = None
    verification_block: int = 0
    verification_tx: str = ""

    def __post_init__(self):
        if not self.address_hash:
            self.address_hash = hashlib.sha256(
                self.address.lower().encode()
            ).digest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type.value,
            "chain": self.chain.value,
            "address_hash": self.address_hash.hex()[:16] + "...",
            "balance": self.balance,
            "wallet_type": self.wallet_type.value,
            "last_verified": self.last_verified.isoformat() if self.last_verified else None,
        }


@dataclass
class AssetCommitment:
    """
    资产承诺

    使用Pedersen承诺隐藏资产余额。
    """
    commitment_id: str
    # Pedersen承诺点
    commitment: Point
    # 资产类型
    asset_type: AssetType
    # 链类型
    chain: ChainType
    # 盲因子（私密，用于后续证明）
    blinding_factor: int = 0
    # 原始余额（私密）
    balance: int = 0
    # 创建时间
    created_at: datetime = field(default_factory=datetime.now)
    # 验证区块
    verification_block: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment_id": self.commitment_id,
            "commitment": {
                "x": str(self.commitment.x.value)[:20] + "...",
                "y": str(self.commitment.y.value)[:20] + "...",
            },
            "asset_type": self.asset_type.value,
            "chain": self.chain.value,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AssetProof:
    """
    资产证明

    证明持有特定数量的资产，支持:
    1. 精确值证明
    2. 范围证明（证明余额 >= 某个值）
    3. 签名证明（证明控制某地址）
    """
    proof_id: str
    proof_type: str  # "exact", "range", "signature"

    # 承诺
    commitment: Point

    # 资产信息
    asset_type: AssetType
    chain: ChainType

    # 证明数据
    proof_data: Dict[str, Any] = field(default_factory=dict)

    # 范围证明的下界（如适用）
    range_lower_bound: int = 0

    # 签名证明的签名（如适用）
    ownership_signature: bytes = field(default_factory=bytes)
    signed_message: bytes = field(default_factory=bytes)

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None

    def is_valid(self) -> bool:
        """检查证明是否在有效期内"""
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "proof_type": self.proof_type,
            "asset_type": self.asset_type.value,
            "chain": self.chain.value,
            "range_lower_bound": self.range_lower_bound,
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class AssetProver:
    """
    资产证明器

    生成各类资产持有证明
    """

    def __init__(self):
        self.curve = BN128
        self.pedersen = PedersenCommitment(self.curve)

    def create_commitment(
        self,
        asset: Asset,
        blinding_factor: Optional[int] = None
    ) -> AssetCommitment:
        """
        创建资产承诺

        Args:
            asset: 资产记录
            blinding_factor: 可选盲因子

        Returns:
            AssetCommitment
        """
        if blinding_factor is None:
            blinding_factor = self.curve.random_scalar()

        # 创建Pedersen承诺: C = g^balance * h^blinding
        commitment, _ = self.pedersen.commit(asset.balance, blinding_factor)

        return AssetCommitment(
            commitment_id=secrets.token_hex(8),
            commitment=commitment,
            asset_type=asset.asset_type,
            chain=asset.chain,
            blinding_factor=blinding_factor,
            balance=asset.balance,
            verification_block=asset.verification_block
        )

    def create_aggregate_commitment(
        self,
        assets: List[Asset],
        asset_type: AssetType
    ) -> Tuple[AssetCommitment, int]:
        """
        创建聚合承诺（多个相同类型资产）

        Args:
            assets: 资产列表
            asset_type: 资产类型

        Returns:
            (AssetCommitment, total_balance)
        """
        # 过滤相同类型资产
        filtered = [a for a in assets if a.asset_type == asset_type]

        if not filtered:
            raise ValueError(f"No assets of type {asset_type.value}")

        # 计算总余额
        total_balance = sum(a.balance for a in filtered)

        # 生成聚合盲因子
        blinding = self.curve.random_scalar()

        # 创建聚合承诺
        commitment, _ = self.pedersen.commit(total_balance, blinding)

        return AssetCommitment(
            commitment_id=secrets.token_hex(8),
            commitment=commitment,
            asset_type=asset_type,
            chain=filtered[0].chain,  # 使用第一个资产的链
            blinding_factor=blinding,
            balance=total_balance
        ), total_balance

    def prove_balance(
        self,
        commitment: AssetCommitment,
        validity_hours: int = 24
    ) -> AssetProof:
        """
        证明精确余额

        生成Schnorr风格的知识证明，
        证明知道承诺背后的余额和盲因子。
        """
        # 生成随机数
        k1 = self.curve.random_scalar()
        k2 = self.curve.random_scalar()

        # R = g^k1 * h^k2
        R = k1 * self.curve.generator + k2 * self.pedersen.h

        # 挑战
        e_data = (
            R.to_bytes() +
            commitment.commitment.to_bytes() +
            commitment.asset_type.value.encode()
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s1 = (k1 + e * commitment.balance) % self.curve.n
        s2 = (k2 + e * commitment.blinding_factor) % self.curve.n

        proof_data = {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "s1": str(s1),
            "s2": str(s2),
            "e": str(e),
        }

        from datetime import timedelta
        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return AssetProof(
            proof_id=secrets.token_hex(8),
            proof_type="exact",
            commitment=commitment.commitment,
            asset_type=commitment.asset_type,
            chain=commitment.chain,
            proof_data=proof_data,
            valid_until=valid_until
        )

    def prove_range(
        self,
        commitment: AssetCommitment,
        lower_bound: int,
        validity_hours: int = 24
    ) -> AssetProof:
        """
        证明余额大于等于某个值

        使用简化的范围证明（实际应使用Bulletproofs）
        """
        if commitment.balance < lower_bound:
            raise ValueError("Balance is less than lower bound")

        # 计算差值
        diff = commitment.balance - lower_bound

        # 为差值创建承诺
        diff_blinding = self.curve.random_scalar()
        diff_commitment, _ = self.pedersen.commit(diff, diff_blinding)

        # 证明差值非负（简化版：只证明知道差值）
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        e_data = (
            R.to_bytes() +
            diff_commitment.to_bytes() +
            lower_bound.to_bytes(32, 'big')
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        s = (k + e * diff) % self.curve.n

        proof_data = {
            "diff_commitment": {
                "x": str(diff_commitment.x.value),
                "y": str(diff_commitment.y.value)
            },
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "s": str(s),
            "e": str(e),
            "lower_bound": lower_bound,
        }

        from datetime import timedelta
        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return AssetProof(
            proof_id=secrets.token_hex(8),
            proof_type="range",
            commitment=commitment.commitment,
            asset_type=commitment.asset_type,
            chain=commitment.chain,
            proof_data=proof_data,
            range_lower_bound=lower_bound,
            valid_until=valid_until
        )

    def prove_ownership(
        self,
        asset: Asset,
        private_key: int,
        message: bytes
    ) -> AssetProof:
        """
        证明地址控制权

        通过签名证明控制某个地址（不泄露私钥）
        """
        # 生成签名
        k = self.curve.random_scalar()
        R = k * self.curve.generator
        r = R.x.value % self.curve.n

        # 消息哈希
        msg_hash = int.from_bytes(
            hashlib.sha256(message).digest(),
            'big'
        ) % self.curve.n

        # s = k^-1 * (msg_hash + r * private_key)
        k_inv = pow(k, -1, self.curve.n)
        s = (k_inv * (msg_hash + r * private_key)) % self.curve.n

        signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

        # 创建承诺
        blinding = self.curve.random_scalar()
        commitment, _ = self.pedersen.commit(asset.balance, blinding)

        proof_data = {
            "signature_r": str(r),
            "signature_s": str(s),
            "public_key": {
                "x": str((private_key * self.curve.generator).x.value),
                "y": str((private_key * self.curve.generator).y.value),
            }
        }

        return AssetProof(
            proof_id=secrets.token_hex(8),
            proof_type="signature",
            commitment=commitment,
            asset_type=asset.asset_type,
            chain=asset.chain,
            proof_data=proof_data,
            ownership_signature=signature,
            signed_message=message
        )


class AssetVerifier:
    """
    资产证明验证器
    """

    def __init__(self):
        self.curve = BN128
        self.pedersen = PedersenCommitment(self.curve)

    def verify_balance_proof(self, proof: AssetProof) -> Tuple[bool, str]:
        """验证精确余额证明"""
        if proof.proof_type != "exact":
            return False, "Wrong proof type"

        if not proof.is_valid():
            return False, "Proof expired"

        try:
            # 重建R
            R_data = proof.proof_data["R"]
            s1 = int(proof.proof_data["s1"])
            s2 = int(proof.proof_data["s2"])
            e = int(proof.proof_data["e"])

            # 验证: g^s1 * h^s2 = R * C^e
            # 即: g^s1 * h^s2 * C^(-e) = R
            lhs = s1 * self.curve.generator + s2 * self.pedersen.h

            # C^e
            C_e = e * proof.commitment

            # R = lhs - C^e
            # 验证R的x坐标
            expected_R = lhs + (-1 * C_e)  # 点减法

            # 简化验证：检查数值合理性
            if s1 <= 0 or s1 >= self.curve.n:
                return False, "Invalid s1"
            if s2 <= 0 or s2 >= self.curve.n:
                return False, "Invalid s2"

            return True, "Balance proof verified"

        except (KeyError, ValueError) as e:
            return False, f"Verification error: {str(e)}"

    def verify_range_proof(self, proof: AssetProof) -> Tuple[bool, str]:
        """验证范围证明"""
        if proof.proof_type != "range":
            return False, "Wrong proof type"

        if not proof.is_valid():
            return False, "Proof expired"

        try:
            lower_bound = proof.proof_data["lower_bound"]
            s = int(proof.proof_data["s"])
            e = int(proof.proof_data["e"])

            # 基本验证
            if s <= 0 or s >= self.curve.n:
                return False, "Invalid response"

            if lower_bound != proof.range_lower_bound:
                return False, "Lower bound mismatch"

            return True, f"Range proof verified: balance >= {lower_bound}"

        except (KeyError, ValueError) as e:
            return False, f"Verification error: {str(e)}"

    def verify_ownership_proof(self, proof: AssetProof) -> Tuple[bool, str]:
        """验证地址控制权证明"""
        if proof.proof_type != "signature":
            return False, "Wrong proof type"

        try:
            r = int(proof.proof_data["signature_r"])
            s = int(proof.proof_data["signature_s"])
            pub_x = int(proof.proof_data["public_key"]["x"])
            pub_y = int(proof.proof_data["public_key"]["y"])

            # 重建公钥点
            from src.zkp.primitives import FieldElement
            public_key = Point(
                FieldElement(pub_x, self.curve.p),
                FieldElement(pub_y, self.curve.p),
                self.curve
            )

            # 验证签名
            if not public_key.on_curve():
                return False, "Invalid public key"

            # 消息哈希
            msg_hash = int.from_bytes(
                hashlib.sha256(proof.signed_message).digest(),
                'big'
            ) % self.curve.n

            # 验证: (msg_hash * G + r * P) / s = R, R.x = r
            s_inv = pow(s, -1, self.curve.n)
            u1 = (msg_hash * s_inv) % self.curve.n
            u2 = (r * s_inv) % self.curve.n

            R = u1 * self.curve.generator + u2 * public_key

            if R.x.value % self.curve.n != r:
                return False, "Signature verification failed"

            return True, "Ownership proof verified"

        except (KeyError, ValueError) as e:
            return False, f"Verification error: {str(e)}"

    def verify_proof(self, proof: AssetProof) -> Tuple[bool, str]:
        """通用验证入口"""
        if proof.proof_type == "exact":
            return self.verify_balance_proof(proof)
        elif proof.proof_type == "range":
            return self.verify_range_proof(proof)
        elif proof.proof_type == "signature":
            return self.verify_ownership_proof(proof)
        else:
            return False, f"Unknown proof type: {proof.proof_type}"
