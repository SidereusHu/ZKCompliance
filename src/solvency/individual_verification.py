"""
Individual Verification - 用户独立验证

允许用户独立验证自己的余额是否被正确包含在储备金证明中，
而无需信任交易所或审计方。

关键特性:
1. 无需查看其他用户数据
2. 可离线验证
3. 支持多资产验证
4. 与储备金证明密码学绑定
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple, Any
from datetime import datetime
from enum import Enum
import hashlib
import secrets

from src.solvency.merkle_sum_tree import (
    MerkleSumTree,
    InclusionProof,
    UserBalance,
    AssetType,
)
from src.solvency.proof_of_reserves import (
    ProofOfReserves,
    SolvencyStatus,
)


class VerificationStatus(Enum):
    """验证状态"""
    VERIFIED = "verified"  # 验证通过
    FAILED = "failed"  # 验证失败
    PENDING = "pending"  # 待验证
    EXPIRED = "expired"  # 已过期


@dataclass
class UserProof:
    """
    用户证明包

    用户从交易所获取的证明数据，用于独立验证。
    """
    proof_id: str

    # 用户信息
    user_id: str  # 用户ID（仅用户自己知道）
    user_hash: bytes  # 用户哈希（用于验证）

    # 余额信息
    balance: int
    asset_type: AssetType

    # 包含证明
    inclusion_proof: InclusionProof

    # 关联的储备金证明
    reserves_proof_id: str
    reserves_root_hash: bytes
    reserves_total_liabilities: int

    # 元数据
    exchange_id: str
    exchange_name: str
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None

    # 验证状态
    verification_status: VerificationStatus = VerificationStatus.PENDING
    verified_at: Optional[datetime] = None

    def is_valid(self) -> bool:
        """检查证明是否在有效期内"""
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "user_hash": self.user_hash.hex()[:16] + "...",
            "balance": self.balance,
            "asset_type": self.asset_type.value,
            "exchange": {
                "id": self.exchange_id,
                "name": self.exchange_name,
            },
            "reserves_root_hash": self.reserves_root_hash.hex()[:32] + "...",
            "reserves_total_liabilities": self.reserves_total_liabilities,
            "verification_status": self.verification_status.value,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class VerificationResult:
    """验证结果"""
    result_id: str

    # 验证状态
    is_valid: bool
    status: VerificationStatus

    # 验证的用户证明
    user_proof_id: str
    user_hash: bytes

    # 验证详情
    balance_verified: bool
    inclusion_verified: bool
    root_hash_matched: bool
    total_liabilities_matched: bool

    # 错误信息
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # 元数据
    verified_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "is_valid": self.is_valid,
            "status": self.status.value,
            "details": {
                "balance_verified": self.balance_verified,
                "inclusion_verified": self.inclusion_verified,
                "root_hash_matched": self.root_hash_matched,
                "total_liabilities_matched": self.total_liabilities_matched,
            },
            "errors": self.errors,
            "warnings": self.warnings,
            "verified_at": self.verified_at.isoformat(),
        }


class UserVerifier:
    """
    用户验证器

    允许用户独立验证自己的余额包含证明。
    """

    def __init__(self):
        self.verification_history: List[VerificationResult] = []

    def create_user_proof(
        self,
        user_id: str,
        balance: int,
        asset_type: AssetType,
        inclusion_proof: InclusionProof,
        reserves_proof: ProofOfReserves,
        nonce: Optional[bytes] = None
    ) -> UserProof:
        """
        创建用户证明包

        Args:
            user_id: 用户ID
            balance: 用户余额
            asset_type: 资产类型
            inclusion_proof: 包含证明
            reserves_proof: 储备金证明

        Returns:
            UserProof
        """
        # 计算用户哈希
        if nonce is None:
            nonce = secrets.token_bytes(16)

        user_hash = hashlib.sha256(
            user_id.encode() + nonce
        ).digest()

        return UserProof(
            proof_id=secrets.token_hex(8),
            user_id=user_id,
            user_hash=user_hash,
            balance=balance,
            asset_type=asset_type,
            inclusion_proof=inclusion_proof,
            reserves_proof_id=reserves_proof.proof_id,
            reserves_root_hash=reserves_proof.liability_root,
            reserves_total_liabilities=reserves_proof.total_liabilities,
            exchange_id=reserves_proof.exchange_id,
            exchange_name=reserves_proof.exchange_name,
            valid_until=reserves_proof.valid_until
        )

    def verify_user_proof(
        self,
        user_proof: UserProof,
        expected_balance: Optional[int] = None,
        reserves_proof: Optional[ProofOfReserves] = None
    ) -> VerificationResult:
        """
        验证用户证明

        Args:
            user_proof: 用户证明包
            expected_balance: 预期余额（可选，用于额外验证）
            reserves_proof: 储备金证明（可选，用于交叉验证）

        Returns:
            VerificationResult
        """
        errors = []
        warnings = []

        # 1. 检查有效期
        if not user_proof.is_valid():
            return VerificationResult(
                result_id=secrets.token_hex(8),
                is_valid=False,
                status=VerificationStatus.EXPIRED,
                user_proof_id=user_proof.proof_id,
                user_hash=user_proof.user_hash,
                balance_verified=False,
                inclusion_verified=False,
                root_hash_matched=False,
                total_liabilities_matched=False,
                errors=["Proof has expired"]
            )

        # 2. 验证余额匹配
        balance_verified = True
        if expected_balance is not None:
            if user_proof.balance != expected_balance:
                balance_verified = False
                errors.append(
                    f"Balance mismatch: expected {expected_balance}, "
                    f"got {user_proof.balance}"
                )

        # 3. 验证包含证明
        inclusion_verified, msg = self._verify_inclusion(user_proof)
        if not inclusion_verified:
            errors.append(f"Inclusion proof failed: {msg}")

        # 4. 验证根哈希
        root_hash_matched = True
        if user_proof.inclusion_proof.root_hash != user_proof.reserves_root_hash:
            root_hash_matched = False
            errors.append("Root hash mismatch")

        # 5. 验证总负债
        total_liabilities_matched = True
        if user_proof.inclusion_proof.total_liabilities != user_proof.reserves_total_liabilities:
            total_liabilities_matched = False
            errors.append("Total liabilities mismatch")

        # 6. 如果提供了储备金证明，进行交叉验证
        if reserves_proof:
            if reserves_proof.liability_root != user_proof.reserves_root_hash:
                warnings.append("Reserves proof root hash differs from user proof")

            if reserves_proof.total_liabilities != user_proof.reserves_total_liabilities:
                warnings.append("Reserves proof total liabilities differs")

            if reserves_proof.status == SolvencyStatus.INSOLVENT:
                warnings.append("Exchange is reported as insolvent")

        # 判断最终结果
        is_valid = (
            balance_verified and
            inclusion_verified and
            root_hash_matched and
            total_liabilities_matched and
            len(errors) == 0
        )

        status = VerificationStatus.VERIFIED if is_valid else VerificationStatus.FAILED

        # 更新用户证明状态
        user_proof.verification_status = status
        user_proof.verified_at = datetime.now()

        result = VerificationResult(
            result_id=secrets.token_hex(8),
            is_valid=is_valid,
            status=status,
            user_proof_id=user_proof.proof_id,
            user_hash=user_proof.user_hash,
            balance_verified=balance_verified,
            inclusion_verified=inclusion_verified,
            root_hash_matched=root_hash_matched,
            total_liabilities_matched=total_liabilities_matched,
            errors=errors,
            warnings=warnings
        )

        self.verification_history.append(result)
        return result

    def _verify_inclusion(
        self,
        user_proof: UserProof
    ) -> Tuple[bool, str]:
        """验证包含证明"""
        proof = user_proof.inclusion_proof

        # 重建叶子哈希
        user_balance = UserBalance(
            user_id="",
            user_hash=proof.user_hash,
            balance=proof.balance,
            asset_type=proof.asset_type
        )
        current_hash = user_balance.compute_leaf_hash()
        current_sum = proof.balance

        # 沿路径向上验证
        for sibling_hash, sibling_sum, is_left in proof.proof_path:
            if is_left:
                combined = (
                    sibling_hash +
                    current_hash +
                    sibling_sum.to_bytes(32, 'big') +
                    current_sum.to_bytes(32, 'big')
                )
            else:
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
            return False, "Root hash mismatch after path verification"

        # 验证总负债
        if current_sum != proof.total_liabilities:
            return False, "Total liabilities mismatch after path verification"

        return True, "Inclusion verified"

    def batch_verify(
        self,
        user_proofs: List[UserProof],
        reserves_proof: Optional[ProofOfReserves] = None
    ) -> List[VerificationResult]:
        """
        批量验证用户证明

        Args:
            user_proofs: 用户证明列表
            reserves_proof: 储备金证明

        Returns:
            验证结果列表
        """
        return [
            self.verify_user_proof(up, reserves_proof=reserves_proof)
            for up in user_proofs
        ]

    def get_verification_summary(self) -> Dict[str, Any]:
        """获取验证历史摘要"""
        total = len(self.verification_history)
        verified = sum(1 for r in self.verification_history if r.is_valid)
        failed = total - verified

        return {
            "total_verifications": total,
            "verified": verified,
            "failed": failed,
            "success_rate": verified / total if total > 0 else 0.0,
        }


class UserProofExporter:
    """
    用户证明导出器

    支持将用户证明导出为各种格式，方便用户保存和分享。
    """

    @staticmethod
    def to_json(user_proof: UserProof) -> str:
        """导出为JSON格式"""
        import json

        data = {
            "proof_id": user_proof.proof_id,
            "user_hash": user_proof.user_hash.hex(),
            "balance": user_proof.balance,
            "asset_type": user_proof.asset_type.value,
            "inclusion_proof": {
                "user_hash": user_proof.inclusion_proof.user_hash.hex(),
                "balance": user_proof.inclusion_proof.balance,
                "asset_type": user_proof.inclusion_proof.asset_type.value,
                "proof_path": [
                    {
                        "hash": h.hex(),
                        "sum": s,
                        "is_left": l
                    }
                    for h, s, l in user_proof.inclusion_proof.proof_path
                ],
                "leaf_index": user_proof.inclusion_proof.leaf_index,
                "root_hash": user_proof.inclusion_proof.root_hash.hex(),
                "total_liabilities": user_proof.inclusion_proof.total_liabilities,
            },
            "reserves_proof_id": user_proof.reserves_proof_id,
            "reserves_root_hash": user_proof.reserves_root_hash.hex(),
            "reserves_total_liabilities": user_proof.reserves_total_liabilities,
            "exchange": {
                "id": user_proof.exchange_id,
                "name": user_proof.exchange_name,
            },
            "created_at": user_proof.created_at.isoformat(),
            "valid_until": user_proof.valid_until.isoformat() if user_proof.valid_until else None,
        }

        return json.dumps(data, indent=2)

    @staticmethod
    def from_json(json_str: str) -> UserProof:
        """从JSON导入"""
        import json
        data = json.loads(json_str)

        inclusion_proof = InclusionProof(
            user_hash=bytes.fromhex(data["inclusion_proof"]["user_hash"]),
            balance=data["inclusion_proof"]["balance"],
            asset_type=AssetType(data["inclusion_proof"]["asset_type"]),
            proof_path=[
                (
                    bytes.fromhex(p["hash"]),
                    p["sum"],
                    p["is_left"]
                )
                for p in data["inclusion_proof"]["proof_path"]
            ],
            leaf_index=data["inclusion_proof"]["leaf_index"],
            root_hash=bytes.fromhex(data["inclusion_proof"]["root_hash"]),
            total_liabilities=data["inclusion_proof"]["total_liabilities"],
        )

        valid_until = None
        if data.get("valid_until"):
            valid_until = datetime.fromisoformat(data["valid_until"])

        return UserProof(
            proof_id=data["proof_id"],
            user_id="",  # 不存储原始user_id
            user_hash=bytes.fromhex(data["user_hash"]),
            balance=data["balance"],
            asset_type=AssetType(data["asset_type"]),
            inclusion_proof=inclusion_proof,
            reserves_proof_id=data["reserves_proof_id"],
            reserves_root_hash=bytes.fromhex(data["reserves_root_hash"]),
            reserves_total_liabilities=data["reserves_total_liabilities"],
            exchange_id=data["exchange"]["id"],
            exchange_name=data["exchange"]["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            valid_until=valid_until,
        )

    @staticmethod
    def to_qr_data(user_proof: UserProof) -> bytes:
        """
        生成QR码数据

        压缩关键数据用于生成QR码。
        """
        # 压缩格式：
        # - proof_id (16 bytes)
        # - user_hash (32 bytes)
        # - balance (32 bytes, big-endian)
        # - root_hash (32 bytes)
        # - total_liabilities (32 bytes, big-endian)

        proof_id_bytes = bytes.fromhex(user_proof.proof_id)[:16]
        proof_id_bytes = proof_id_bytes.ljust(16, b'\x00')

        data = (
            proof_id_bytes +
            user_proof.user_hash[:32] +
            user_proof.balance.to_bytes(32, 'big') +
            user_proof.reserves_root_hash[:32] +
            user_proof.reserves_total_liabilities.to_bytes(32, 'big')
        )

        return data
