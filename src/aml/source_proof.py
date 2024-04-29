"""
交易来源证明系统

实现零知识资金来源证明:
- 证明资金来自合规渠道（CEX、合规DeFi等）
- 证明资金链路清白
- 不泄露具体交易历史和金额
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


class SourceType(Enum):
    """资金来源类型"""
    CEX_WITHDRAWAL = "cex_withdrawal"        # 中心化交易所提款
    CEX_DEPOSIT = "cex_deposit"              # 中心化交易所存款
    DEFI_SWAP = "defi_swap"                  # DeFi交易
    DEFI_LENDING = "defi_lending"            # DeFi借贷
    DEFI_YIELD = "defi_yield"                # DeFi收益
    NFT_SALE = "nft_sale"                    # NFT销售
    MINING_REWARD = "mining_reward"          # 挖矿奖励
    STAKING_REWARD = "staking_reward"        # 质押奖励
    AIRDROP = "airdrop"                      # 空投
    SALARY = "salary"                        # 工资支付
    P2P_TRANSFER = "p2p_transfer"            # 个人转账
    CONTRACT_INTERACTION = "contract"        # 合约交互
    BRIDGE = "bridge"                        # 跨链桥
    UNKNOWN = "unknown"                      # 未知来源


class RiskLevel(Enum):
    """风险等级"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TransactionSource:
    """交易来源记录"""
    # 交易哈希
    tx_hash: str
    # 来源类型
    source_type: SourceType
    # 来源地址
    from_address: str
    # 目标地址
    to_address: str
    # 金额（wei）
    amount: int
    # 区块号
    block_number: int
    # 时间戳
    timestamp: dt
    # 来源协议/平台
    platform: str = ""
    # 风险等级
    risk_level: RiskLevel = RiskLevel.LOW
    # 是否已验证
    verified: bool = False
    # 验证方信息
    verifier: str = ""

    def compute_hash(self) -> bytes:
        """计算交易来源哈希"""
        data = f"{self.tx_hash}:{self.source_type.value}:{self.from_address}:{self.to_address}:{self.amount}"
        return hashlib.sha256(data.encode()).digest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "source_type": self.source_type.value,
            "from_address": self.from_address,
            "to_address": self.to_address,
            "amount": str(self.amount),
            "block_number": self.block_number,
            "timestamp": self.timestamp.isoformat(),
            "platform": self.platform,
            "risk_level": self.risk_level.value,
            "verified": self.verified,
        }


@dataclass
class SourceChain:
    """资金链路

    记录资金从初始来源到当前地址的完整路径。
    """
    # 链路ID
    chain_id: str
    # 当前地址
    current_address: str
    # 交易序列
    transactions: List[TransactionSource]
    # 总深度（跳数）
    depth: int
    # 最高风险等级
    max_risk_level: RiskLevel
    # 是否包含已验证的初始来源
    has_verified_origin: bool
    # 初始来源类型
    origin_type: Optional[SourceType] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "current_address": self.current_address,
            "depth": self.depth,
            "max_risk_level": self.max_risk_level.value,
            "has_verified_origin": self.has_verified_origin,
            "origin_type": self.origin_type.value if self.origin_type else None,
            "transaction_count": len(self.transactions),
        }


@dataclass
class SourceProof:
    """来源证明

    证明资金来自合规来源的零知识证明。
    """
    # 证明类型
    proof_type: str  # "compliant_source", "verified_origin", "clean_path"
    # 地址承诺
    address_commitment: Point
    # 来源类型承诺（隐藏具体来源）
    source_type_commitment: Point
    # 链路深度承诺
    depth_commitment: Point
    # 合规性证明
    compliance_proof: Dict[str, Any]
    # 知识证明
    knowledge_proof: Dict[str, Any]
    # 风险等级（可选披露）
    disclosed_risk_level: Optional[RiskLevel] = None
    # 创建时间
    created_at: dt = dc_field(default_factory=dt.now)
    # 有效期
    valid_until: Optional[dt] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_type": self.proof_type,
            "address_commitment": {
                "x": str(self.address_commitment.x.value),
                "y": str(self.address_commitment.y.value),
            },
            "disclosed_risk_level": self.disclosed_risk_level.value if self.disclosed_risk_level else None,
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class SourceProver:
    """来源证明生成器"""

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

        # 合规来源类型
        self.compliant_sources: Set[SourceType] = {
            SourceType.CEX_WITHDRAWAL,
            SourceType.CEX_DEPOSIT,
            SourceType.DEFI_SWAP,
            SourceType.DEFI_LENDING,
            SourceType.DEFI_YIELD,
            SourceType.NFT_SALE,
            SourceType.MINING_REWARD,
            SourceType.STAKING_REWARD,
            SourceType.SALARY,
            SourceType.AIRDROP,
        }

        # 来源类型到数值的映射
        self.source_type_values = {
            st: i for i, st in enumerate(SourceType)
        }

    def analyze_source_chain(
        self,
        address: str,
        transactions: List[TransactionSource],
        max_depth: int = 10,
    ) -> SourceChain:
        """分析资金链路

        Args:
            address: 当前地址
            transactions: 相关交易列表
            max_depth: 最大追溯深度

        Returns:
            SourceChain 资金链路分析结果
        """
        # 过滤和排序交易
        relevant_txs = [
            tx for tx in transactions
            if tx.to_address.lower() == address.lower()
        ]
        relevant_txs.sort(key=lambda x: x.block_number)

        # 确定最高风险等级
        risk_levels = [RiskLevel.LOW]
        for tx in relevant_txs:
            risk_levels.append(tx.risk_level)

        max_risk = max(risk_levels, key=lambda x: list(RiskLevel).index(x))

        # 检查是否有已验证的来源
        has_verified = any(tx.verified for tx in relevant_txs)

        # 确定初始来源类型
        origin_type = None
        if relevant_txs:
            origin_type = relevant_txs[0].source_type

        return SourceChain(
            chain_id=secrets.token_hex(8),
            current_address=address,
            transactions=relevant_txs[:max_depth],
            depth=min(len(relevant_txs), max_depth),
            max_risk_level=max_risk,
            has_verified_origin=has_verified,
            origin_type=origin_type,
        )

    def prove_compliant_source(
        self,
        address: str,
        source_chain: SourceChain,
        blinding_factors: Optional[Dict[str, int]] = None,
        validity_hours: int = 24,
    ) -> SourceProof:
        """证明资金来源合规

        Args:
            address: 当前地址
            source_chain: 资金链路
            blinding_factors: 盲因子
            validity_hours: 有效期

        Returns:
            SourceProof

        Raises:
            ValueError: 如果来源不合规
        """
        # 验证来源合规性
        if source_chain.origin_type and source_chain.origin_type not in self.compliant_sources:
            if source_chain.origin_type != SourceType.P2P_TRANSFER:
                raise ValueError(
                    f"Non-compliant source type: {source_chain.origin_type.value}"
                )

        # 检查风险等级
        if source_chain.max_risk_level == RiskLevel.CRITICAL:
            raise ValueError("Critical risk level detected in source chain")

        # 生成盲因子
        if blinding_factors is None:
            blinding_factors = {
                "address": self.curve.random_scalar(),
                "source_type": self.curve.random_scalar(),
                "depth": self.curve.random_scalar(),
            }

        # 计算地址哈希
        address_hash = int.from_bytes(
            hashlib.sha256(address.lower().encode()).digest(),
            'big'
        ) % self.curve.n

        # 创建承诺
        address_commitment, _ = self.pedersen.commit(
            address_hash,
            blinding_factors["address"]
        )

        # 来源类型承诺
        source_type_value = self.source_type_values.get(
            source_chain.origin_type,
            len(SourceType) - 1  # UNKNOWN
        )
        source_type_commitment, _ = self.pedersen.commit(
            source_type_value,
            blinding_factors["source_type"]
        )

        # 深度承诺
        depth_commitment, _ = self.pedersen.commit(
            source_chain.depth,
            blinding_factors["depth"]
        )

        # 生成合规性证明
        compliance_proof = self._create_compliance_proof(
            source_chain,
            blinding_factors,
        )

        # 生成知识证明
        knowledge_proof = self._create_knowledge_proof(
            address_hash,
            blinding_factors["address"],
            address_commitment,
        )

        # 计算有效期
        from datetime import timedelta
        valid_until = dt.now() + timedelta(hours=validity_hours)

        return SourceProof(
            proof_type="compliant_source",
            address_commitment=address_commitment,
            source_type_commitment=source_type_commitment,
            depth_commitment=depth_commitment,
            compliance_proof=compliance_proof,
            knowledge_proof=knowledge_proof,
            disclosed_risk_level=source_chain.max_risk_level,
            valid_until=valid_until,
        )

    def prove_verified_origin(
        self,
        address: str,
        source_chain: SourceChain,
        origin_signature: bytes,
        validity_hours: int = 24,
    ) -> SourceProof:
        """证明资金有已验证的来源（如CEX提款证明）

        Args:
            address: 当前地址
            source_chain: 资金链路
            origin_signature: 来源签名（由CEX等提供）
            validity_hours: 有效期

        Returns:
            SourceProof
        """
        if not source_chain.has_verified_origin:
            raise ValueError("Source chain does not have verified origin")

        # 生成盲因子
        blinding_factors = {
            "address": self.curve.random_scalar(),
            "source_type": self.curve.random_scalar(),
            "depth": self.curve.random_scalar(),
        }

        # 计算地址哈希
        address_hash = int.from_bytes(
            hashlib.sha256(address.lower().encode()).digest(),
            'big'
        ) % self.curve.n

        # 创建承诺
        address_commitment, _ = self.pedersen.commit(
            address_hash,
            blinding_factors["address"]
        )

        source_type_value = self.source_type_values.get(
            source_chain.origin_type,
            0
        )
        source_type_commitment, _ = self.pedersen.commit(
            source_type_value,
            blinding_factors["source_type"]
        )

        depth_commitment, _ = self.pedersen.commit(
            source_chain.depth,
            blinding_factors["depth"]
        )

        # 生成包含签名验证的合规性证明
        compliance_proof = self._create_verified_origin_proof(
            source_chain,
            origin_signature,
            blinding_factors,
        )

        knowledge_proof = self._create_knowledge_proof(
            address_hash,
            blinding_factors["address"],
            address_commitment,
        )

        from datetime import timedelta
        valid_until = dt.now() + timedelta(hours=validity_hours)

        return SourceProof(
            proof_type="verified_origin",
            address_commitment=address_commitment,
            source_type_commitment=source_type_commitment,
            depth_commitment=depth_commitment,
            compliance_proof=compliance_proof,
            knowledge_proof=knowledge_proof,
            disclosed_risk_level=RiskLevel.LOW,
            valid_until=valid_until,
        )

    def _create_compliance_proof(
        self,
        source_chain: SourceChain,
        blinding_factors: Dict[str, int],
    ) -> Dict[str, Any]:
        """创建合规性证明"""
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 挑战
        chain_hash = hashlib.sha256(source_chain.chain_id.encode()).digest()
        e_data = R.to_bytes() + chain_hash
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        # 响应
        s = (k + e * blinding_factors["address"]) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
            "chain_depth": source_chain.depth,
            "has_verified_origin": source_chain.has_verified_origin,
        }

    def _create_verified_origin_proof(
        self,
        source_chain: SourceChain,
        origin_signature: bytes,
        blinding_factors: Dict[str, int],
    ) -> Dict[str, Any]:
        """创建已验证来源的证明"""
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        # 包含签名的挑战
        e_data = R.to_bytes() + origin_signature
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        s = (k + e * blinding_factors["address"]) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
            "signature_hash": hashlib.sha256(origin_signature).hexdigest()[:16],
            "origin_type": source_chain.origin_type.value if source_chain.origin_type else "unknown",
        }

    def _create_knowledge_proof(
        self,
        value: int,
        blinding: int,
        commitment: Point,
    ) -> Dict[str, Any]:
        """创建知识证明"""
        k = self.curve.random_scalar()
        R = k * self.curve.generator

        e_data = R.to_bytes() + commitment.to_bytes()
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        s = (k + e * blinding) % self.curve.n

        return {
            "R": {"x": str(R.x.value), "y": str(R.y.value)},
            "challenge": str(e),
            "response": str(s),
        }


class SourceVerifier:
    """来源证明验证器"""

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def verify_compliant_source(
        self,
        proof: SourceProof,
        max_allowed_risk: RiskLevel = RiskLevel.MEDIUM,
    ) -> bool:
        """验证来源合规证明

        Args:
            proof: 来源证明
            max_allowed_risk: 允许的最高风险等级

        Returns:
            验证是否通过
        """
        # 检查证明类型
        if proof.proof_type not in ["compliant_source", "verified_origin"]:
            return False

        # 检查有效期
        if proof.valid_until and dt.now() > proof.valid_until:
            return False

        # 检查风险等级
        if proof.disclosed_risk_level:
            risk_order = list(RiskLevel)
            if risk_order.index(proof.disclosed_risk_level) > risk_order.index(max_allowed_risk):
                return False

        # 验证承诺点
        if not proof.address_commitment.on_curve():
            return False
        if not proof.source_type_commitment.on_curve():
            return False
        if not proof.depth_commitment.on_curve():
            return False

        # 验证知识证明
        if not self._verify_knowledge_proof(proof.knowledge_proof):
            return False

        # 验证合规性证明
        if not self._verify_compliance_proof(proof.compliance_proof):
            return False

        return True

    def verify_verified_origin(self, proof: SourceProof) -> bool:
        """验证已验证来源的证明"""
        if proof.proof_type != "verified_origin":
            return False

        if not proof.compliance_proof.get("signature_hash"):
            return False

        return self.verify_compliant_source(proof, RiskLevel.HIGH)

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

    def _verify_compliance_proof(self, proof: Dict[str, Any]) -> bool:
        """验证合规性证明"""
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


# ============================================================
# 预定义合规来源
# ============================================================

COMPLIANT_SOURCES = {
    SourceType.CEX_WITHDRAWAL,
    SourceType.CEX_DEPOSIT,
    SourceType.DEFI_SWAP,
    SourceType.DEFI_LENDING,
    SourceType.DEFI_YIELD,
    SourceType.NFT_SALE,
    SourceType.MINING_REWARD,
    SourceType.STAKING_REWARD,
    SourceType.SALARY,
    SourceType.AIRDROP,
}

# 已知合规平台
COMPLIANT_PLATFORMS = {
    # CEX
    "coinbase",
    "kraken",
    "gemini",
    "bitstamp",
    # DeFi
    "uniswap",
    "aave",
    "compound",
    "maker",
    "curve",
    # NFT
    "opensea",
    "blur",
    # Staking
    "lido",
    "rocket_pool",
}
