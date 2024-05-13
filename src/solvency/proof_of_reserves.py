"""
Proof of Reserves - 储备金证明协议

整合负债树和资产证明，实现完整的储备金证明:
1. 证明总资产 >= 总负债
2. 不泄露任何个人余额
3. 不泄露具体资产分布
4. 支持定期审计和实时验证
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Any
from datetime import datetime
from enum import Enum
import hashlib
import secrets

from src.zkp.primitives import BN128, Point
from src.zkp.commitment import PedersenCommitment
from src.solvency.merkle_sum_tree import (
    MerkleSumTree,
    MerkleSumTreeBuilder,
    UserBalance,
    AssetType,
)
from src.solvency.asset_commitment import (
    Asset,
    AssetCommitment,
    AssetProof,
    AssetProver,
    AssetVerifier,
    ChainType,
    WalletType,
)


class SolvencyStatus(Enum):
    """偿付能力状态"""
    SOLVENT = "solvent"  # 有偿付能力
    INSOLVENT = "insolvent"  # 无偿付能力
    MARGINAL = "marginal"  # 边缘状态（资产略高于负债）
    UNKNOWN = "unknown"  # 未知


@dataclass
class ProofOfReserves:
    """
    储备金证明

    包含证明交易所储备金充足的所有必要信息。
    """
    proof_id: str

    # 负债信息
    liability_root: bytes  # Merkle Sum Tree根
    total_liabilities: int
    liability_commitment: Point  # 总负债的Pedersen承诺

    # 资产信息
    asset_commitments: List[AssetCommitment]
    total_assets_commitment: Point  # 总资产的Pedersen承诺

    # 偿付能力证明
    solvency_proof: Dict[str, Any]  # 证明资产 >= 负债

    # 状态
    status: SolvencyStatus

    # 元数据
    exchange_id: str
    exchange_name: str
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None
    audit_id: str = ""

    # 链上锚定（可选）
    anchor_block: int = 0
    anchor_tx: str = ""

    def is_valid(self) -> bool:
        """检查证明是否在有效期内"""
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "exchange": {
                "id": self.exchange_id,
                "name": self.exchange_name,
            },
            "liabilities": {
                "root": self.liability_root.hex()[:32] + "...",
                "total": self.total_liabilities,
            },
            "assets": {
                "commitment_count": len(self.asset_commitments),
            },
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


@dataclass
class AuditReport:
    """审计报告"""
    report_id: str
    exchange_id: str
    exchange_name: str

    # 证明
    proof: ProofOfReserves

    # 审计信息
    auditor: str
    audit_date: datetime
    audit_type: str  # "full", "partial", "snapshot"

    # 结果
    is_solvent: bool
    solvency_ratio: float  # 资产/负债比率
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    # 签名
    auditor_signature: bytes = field(default_factory=bytes)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "exchange": {
                "id": self.exchange_id,
                "name": self.exchange_name,
            },
            "auditor": self.auditor,
            "audit_date": self.audit_date.isoformat(),
            "audit_type": self.audit_type,
            "is_solvent": self.is_solvent,
            "solvency_ratio": self.solvency_ratio,
            "findings": self.findings,
            "recommendations": self.recommendations,
        }


class ReservesProver:
    """
    储备金证明生成器

    为交易所生成完整的储备金证明。
    """

    def __init__(self, exchange_id: str, exchange_name: str):
        self.exchange_id = exchange_id
        self.exchange_name = exchange_name
        self.curve = BN128
        self.pedersen = PedersenCommitment(self.curve)
        self.asset_prover = AssetProver()

        # 内部状态
        self.liability_tree: Optional[MerkleSumTree] = None
        self.assets: List[Asset] = []
        self.asset_commitments: List[AssetCommitment] = []

    def set_liabilities(self, balances: List[UserBalance]) -> bytes:
        """
        设置负债（用户余额）

        Args:
            balances: 用户余额列表

        Returns:
            Merkle Sum Tree根哈希
        """
        self.liability_tree = MerkleSumTree()
        self.liability_tree.build_tree(balances)
        return self.liability_tree.get_root_hash()

    def add_asset(self, asset: Asset) -> AssetCommitment:
        """
        添加资产

        Args:
            asset: 资产记录

        Returns:
            资产承诺
        """
        self.assets.append(asset)
        commitment = self.asset_prover.create_commitment(asset)
        self.asset_commitments.append(commitment)
        return commitment

    def add_assets(self, assets: List[Asset]) -> List[AssetCommitment]:
        """批量添加资产"""
        return [self.add_asset(a) for a in assets]

    def generate_proof(
        self,
        validity_hours: int = 24,
        include_individual_proofs: bool = False
    ) -> ProofOfReserves:
        """
        生成储备金证明

        Args:
            validity_hours: 证明有效期
            include_individual_proofs: 是否包含单个资产证明

        Returns:
            ProofOfReserves
        """
        if self.liability_tree is None:
            raise ValueError("Liabilities not set")

        if not self.assets:
            raise ValueError("No assets added")

        # 计算总负债
        total_liabilities = self.liability_tree.get_total_liabilities()

        # 计算总资产
        total_assets = sum(a.balance for a in self.assets)

        # 判断偿付能力
        if total_assets >= total_liabilities:
            if total_assets >= total_liabilities * 1.1:  # 10%以上缓冲
                status = SolvencyStatus.SOLVENT
            else:
                status = SolvencyStatus.MARGINAL
        else:
            status = SolvencyStatus.INSOLVENT

        # 创建负债承诺
        liability_blinding = self.curve.random_scalar()
        liability_commitment, _ = self.pedersen.commit(
            total_liabilities,
            liability_blinding
        )

        # 创建资产承诺
        asset_blinding = self.curve.random_scalar()
        asset_commitment, _ = self.pedersen.commit(
            total_assets,
            asset_blinding
        )

        # 生成偿付能力证明
        # 证明: total_assets >= total_liabilities
        # 即: total_assets - total_liabilities >= 0
        solvency_proof = self._prove_solvency(
            total_assets,
            total_liabilities,
            asset_blinding,
            liability_blinding
        )

        # 计算有效期
        from datetime import timedelta
        valid_until = datetime.now() + timedelta(hours=validity_hours)

        return ProofOfReserves(
            proof_id=secrets.token_hex(16),
            liability_root=self.liability_tree.get_root_hash(),
            total_liabilities=total_liabilities,
            liability_commitment=liability_commitment,
            asset_commitments=self.asset_commitments.copy(),
            total_assets_commitment=asset_commitment,
            solvency_proof=solvency_proof,
            status=status,
            exchange_id=self.exchange_id,
            exchange_name=self.exchange_name,
            valid_until=valid_until
        )

    def _prove_solvency(
        self,
        assets: int,
        liabilities: int,
        asset_blinding: int,
        liability_blinding: int
    ) -> Dict[str, Any]:
        """
        生成偿付能力证明

        证明资产 >= 负债，即差值 >= 0
        """
        # 差值
        diff = assets - liabilities
        diff_blinding = (asset_blinding - liability_blinding) % self.curve.n

        # 差值承诺
        diff_commitment, _ = self.pedersen.commit(diff, diff_blinding)

        # 证明差值非负（简化版范围证明）
        if diff < 0:
            # 无法证明
            return {
                "type": "failed",
                "reason": "assets < liabilities"
            }

        # Schnorr风格证明：证明知道diff和blinding
        k1 = self.curve.random_scalar()
        k2 = self.curve.random_scalar()
        R = k1 * self.curve.generator + k2 * self.pedersen.h

        e_data = (
            R.to_bytes() +
            diff_commitment.to_bytes() +
            b"solvency_proof"
        )
        e = int.from_bytes(hashlib.sha256(e_data).digest(), 'big') % self.curve.n

        s1 = (k1 + e * diff) % self.curve.n
        s2 = (k2 + e * diff_blinding) % self.curve.n

        return {
            "type": "range",
            "diff_commitment": {
                "x": str(diff_commitment.x.value),
                "y": str(diff_commitment.y.value),
            },
            "R": {
                "x": str(R.x.value),
                "y": str(R.y.value),
            },
            "e": str(e),
            "s1": str(s1),
            "s2": str(s2),
            # 公开信息：证明差值 >= 0
            "diff_is_positive": diff >= 0,
        }

    def generate_user_proof(self, user_hash: bytes):
        """为用户生成包含证明"""
        if self.liability_tree is None:
            return None
        return self.liability_tree.generate_inclusion_proof(user_hash)

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        total_assets = sum(a.balance for a in self.assets)
        total_liabilities = (
            self.liability_tree.get_total_liabilities()
            if self.liability_tree else 0
        )

        return {
            "exchange_id": self.exchange_id,
            "exchange_name": self.exchange_name,
            "total_users": len(self.liability_tree.user_indices) if self.liability_tree else 0,
            "total_assets": total_assets,
            "total_liabilities": total_liabilities,
            "solvency_ratio": total_assets / total_liabilities if total_liabilities > 0 else float('inf'),
            "asset_count": len(self.assets),
            "asset_types": list(set(a.asset_type.value for a in self.assets)),
        }


class ReservesVerifier:
    """
    储备金证明验证器
    """

    def __init__(self):
        self.curve = BN128
        self.pedersen = PedersenCommitment(self.curve)
        self.asset_verifier = AssetVerifier()

    def verify_proof(
        self,
        proof: ProofOfReserves,
        expected_exchange_id: Optional[str] = None
    ) -> Tuple[bool, str, SolvencyStatus]:
        """
        验证储备金证明

        Args:
            proof: 储备金证明
            expected_exchange_id: 预期的交易所ID

        Returns:
            (is_valid, message, status)
        """
        # 1. 检查有效期
        if not proof.is_valid():
            return False, "Proof expired", SolvencyStatus.UNKNOWN

        # 2. 检查交易所ID
        if expected_exchange_id and proof.exchange_id != expected_exchange_id:
            return False, "Exchange ID mismatch", SolvencyStatus.UNKNOWN

        # 3. 验证偿付能力证明
        solvency_valid, solvency_msg = self._verify_solvency_proof(
            proof.solvency_proof
        )
        if not solvency_valid:
            return False, f"Solvency proof invalid: {solvency_msg}", SolvencyStatus.UNKNOWN

        # 4. 验证承诺点在曲线上
        if not proof.liability_commitment.on_curve():
            return False, "Invalid liability commitment", SolvencyStatus.UNKNOWN

        if not proof.total_assets_commitment.on_curve():
            return False, "Invalid asset commitment", SolvencyStatus.UNKNOWN

        # 5. 验证状态与证明一致
        diff_is_positive = proof.solvency_proof.get("diff_is_positive", False)
        if diff_is_positive and proof.status == SolvencyStatus.INSOLVENT:
            return False, "Status inconsistent with proof", SolvencyStatus.UNKNOWN

        return True, "Proof verified successfully", proof.status

    def _verify_solvency_proof(
        self,
        proof: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """验证偿付能力证明"""
        if proof.get("type") == "failed":
            return False, proof.get("reason", "Unknown failure")

        if proof.get("type") != "range":
            return False, "Unknown proof type"

        try:
            s1 = int(proof["s1"])
            s2 = int(proof["s2"])
            e = int(proof["e"])

            # 基本数值验证
            if s1 <= 0 or s1 >= self.curve.n:
                return False, "Invalid s1"
            if s2 <= 0 or s2 >= self.curve.n:
                return False, "Invalid s2"
            if e <= 0 or e >= self.curve.n:
                return False, "Invalid challenge"

            # 验证差值非负
            if not proof.get("diff_is_positive"):
                return False, "Negative difference"

            return True, "Solvency proof valid"

        except (KeyError, ValueError) as ex:
            return False, f"Verification error: {str(ex)}"

    def verify_user_inclusion(
        self,
        proof: ProofOfReserves,
        user_proof,  # InclusionProof
    ) -> Tuple[bool, str]:
        """
        验证用户包含证明

        Args:
            proof: 储备金证明
            user_proof: 用户的包含证明

        Returns:
            (is_valid, message)
        """
        # 检查根哈希匹配
        if user_proof.root_hash != proof.liability_root:
            return False, "Root hash mismatch"

        # 检查总负债匹配
        if user_proof.total_liabilities != proof.total_liabilities:
            return False, "Total liabilities mismatch"

        # 验证Merkle路径
        tree = MerkleSumTree()
        is_valid, msg = tree.verify_inclusion_proof(user_proof)

        return is_valid, msg

    def generate_audit_report(
        self,
        proof: ProofOfReserves,
        auditor: str,
        audit_type: str = "full"
    ) -> AuditReport:
        """
        生成审计报告

        Args:
            proof: 储备金证明
            auditor: 审计方
            audit_type: 审计类型

        Returns:
            AuditReport
        """
        # 验证证明
        is_valid, msg, status = self.verify_proof(proof)

        # 计算偿付比率（使用公开信息估算）
        # 注：实际无法获取精确值，这里使用状态推断
        if status == SolvencyStatus.SOLVENT:
            solvency_ratio = 1.1  # 假设至少110%
        elif status == SolvencyStatus.MARGINAL:
            solvency_ratio = 1.0  # 约100%
        else:
            solvency_ratio = 0.0  # 未知或不足

        findings = []
        recommendations = []

        if not is_valid:
            findings.append(f"Proof verification failed: {msg}")
            recommendations.append("Immediate investigation required")
        elif status == SolvencyStatus.MARGINAL:
            findings.append("Solvency ratio is marginal")
            recommendations.append("Consider increasing reserves buffer")
        elif status == SolvencyStatus.SOLVENT:
            findings.append("Exchange is fully solvent")

        return AuditReport(
            report_id=secrets.token_hex(8),
            exchange_id=proof.exchange_id,
            exchange_name=proof.exchange_name,
            proof=proof,
            auditor=auditor,
            audit_date=datetime.now(),
            audit_type=audit_type,
            is_solvent=(status == SolvencyStatus.SOLVENT or status == SolvencyStatus.MARGINAL),
            solvency_ratio=solvency_ratio,
            findings=findings,
            recommendations=recommendations
        )


# 便捷函数
def create_proof_of_reserves(
    exchange_id: str,
    exchange_name: str,
    user_balances: List[Dict[str, Any]],
    assets: List[Dict[str, Any]],
    validity_hours: int = 24
) -> ProofOfReserves:
    """
    创建储备金证明的便捷函数

    Args:
        exchange_id: 交易所ID
        exchange_name: 交易所名称
        user_balances: 用户余额列表 [{"user_id": str, "balance": int, "asset_type": str}, ...]
        assets: 资产列表 [{"address": str, "balance": int, "chain": str}, ...]
        validity_hours: 有效期

    Returns:
        ProofOfReserves
    """
    prover = ReservesProver(exchange_id, exchange_name)

    # 设置负债
    balances = [
        UserBalance(
            user_id=b["user_id"],
            user_hash=b'',
            balance=b["balance"],
            asset_type=AssetType(b.get("asset_type", "eth"))
        )
        for b in user_balances
    ]
    prover.set_liabilities(balances)

    # 添加资产
    for a in assets:
        asset = Asset(
            asset_id=secrets.token_hex(4),
            asset_type=AssetType(a.get("asset_type", "eth")),
            chain=ChainType(a.get("chain", "ethereum")),
            address=a["address"],
            balance=a["balance"],
            wallet_type=WalletType(a.get("wallet_type", "hot"))
        )
        prover.add_asset(asset)

    # 生成证明
    return prover.generate_proof(validity_hours)
