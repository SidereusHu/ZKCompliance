"""
Credit Score System - 信用评分系统

基于链上活动计算隐私保护的信用分数。

评分因素:
1. 账户历史 - 账户年龄、活跃度
2. 交易行为 - 交易频率、金额、稳定性
3. DeFi参与 - 借贷历史、清算情况
4. 资产状况 - 持仓多样性、稳定性
5. 社交信用 - ENS、DAO参与等
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import secrets


class CreditFactorType(Enum):
    """信用因素类型"""
    # 账户历史
    ACCOUNT_AGE = "account_age"
    ACCOUNT_ACTIVITY = "account_activity"
    # 交易行为
    TRANSACTION_VOLUME = "transaction_volume"
    TRANSACTION_FREQUENCY = "transaction_frequency"
    TRANSACTION_DIVERSITY = "transaction_diversity"
    # DeFi参与
    LENDING_HISTORY = "lending_history"
    REPAYMENT_RECORD = "repayment_record"
    LIQUIDATION_HISTORY = "liquidation_history"
    # 资产状况
    ASSET_DIVERSITY = "asset_diversity"
    ASSET_STABILITY = "asset_stability"
    BALANCE_HISTORY = "balance_history"
    # 社交/身份
    ENS_OWNERSHIP = "ens_ownership"
    DAO_PARTICIPATION = "dao_participation"
    NFT_HOLDINGS = "nft_holdings"
    # 负面因素
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BLACKLIST_ASSOCIATION = "blacklist_association"


class ScoreRange(Enum):
    """信用等级"""
    EXCELLENT = "excellent"  # 750-850
    GOOD = "good"  # 650-749
    FAIR = "fair"  # 550-649
    POOR = "poor"  # 450-549
    VERY_POOR = "very_poor"  # 300-449

    @classmethod
    def from_score(cls, score: int) -> 'ScoreRange':
        if score >= 750:
            return cls.EXCELLENT
        elif score >= 650:
            return cls.GOOD
        elif score >= 550:
            return cls.FAIR
        elif score >= 450:
            return cls.POOR
        else:
            return cls.VERY_POOR


@dataclass
class CreditFactor:
    """信用因素"""
    factor_type: CreditFactorType
    name: str
    description: str

    # 原始值
    raw_value: float

    # 标准化得分 (0-100)
    normalized_score: float

    # 权重
    weight: float

    # 加权得分
    weighted_score: float = 0.0

    # 元数据
    data_source: str = "on_chain"
    last_updated: datetime = field(default_factory=datetime.now)
    confidence: float = 1.0  # 数据置信度

    def __post_init__(self):
        self.weighted_score = self.normalized_score * self.weight

    def to_dict(self) -> Dict[str, Any]:
        return {
            "factor_type": self.factor_type.value,
            "name": self.name,
            "raw_value": self.raw_value,
            "normalized_score": self.normalized_score,
            "weight": self.weight,
            "weighted_score": self.weighted_score,
            "confidence": self.confidence,
        }


@dataclass
class CreditScore:
    """信用评分"""
    score_id: str

    # 用户信息
    address: str
    address_hash: bytes

    # 总分 (300-850)
    total_score: int

    # 信用等级
    score_range: ScoreRange

    # 各因素得分
    factors: List[CreditFactor]

    # 属性标签
    attributes: Set[str] = field(default_factory=set)

    # 元数据
    created_at: datetime = field(default_factory=datetime.now)
    valid_until: Optional[datetime] = None
    version: str = "1.0"

    # 承诺（用于零知识证明）
    score_commitment: bytes = field(default_factory=bytes)

    def __post_init__(self):
        if not self.address_hash:
            self.address_hash = hashlib.sha256(
                self.address.lower().encode()
            ).digest()

    def is_valid(self) -> bool:
        if self.valid_until is None:
            return True
        return datetime.now() < self.valid_until

    def get_factor_score(self, factor_type: CreditFactorType) -> Optional[float]:
        for f in self.factors:
            if f.factor_type == factor_type:
                return f.normalized_score
        return None

    def has_attribute(self, attribute: str) -> bool:
        return attribute in self.attributes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score_id": self.score_id,
            "address_hash": self.address_hash.hex()[:16] + "...",
            "total_score": self.total_score,
            "score_range": self.score_range.value,
            "factors": [f.to_dict() for f in self.factors],
            "attributes": list(self.attributes),
            "created_at": self.created_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


class CreditScoreComputer:
    """
    信用评分计算器

    基于链上数据计算信用分数。
    """

    # 默认因素权重
    DEFAULT_WEIGHTS = {
        CreditFactorType.ACCOUNT_AGE: 0.10,
        CreditFactorType.ACCOUNT_ACTIVITY: 0.08,
        CreditFactorType.TRANSACTION_VOLUME: 0.12,
        CreditFactorType.TRANSACTION_FREQUENCY: 0.08,
        CreditFactorType.TRANSACTION_DIVERSITY: 0.05,
        CreditFactorType.LENDING_HISTORY: 0.15,
        CreditFactorType.REPAYMENT_RECORD: 0.18,
        CreditFactorType.LIQUIDATION_HISTORY: 0.10,
        CreditFactorType.ASSET_DIVERSITY: 0.05,
        CreditFactorType.ASSET_STABILITY: 0.05,
        CreditFactorType.ENS_OWNERSHIP: 0.02,
        CreditFactorType.DAO_PARTICIPATION: 0.02,
    }

    def __init__(self, weights: Optional[Dict[CreditFactorType, float]] = None):
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()

    def compute_score(
        self,
        address: str,
        on_chain_data: Dict[str, Any],
        validity_days: int = 30
    ) -> CreditScore:
        """
        计算信用分数

        Args:
            address: 钱包地址
            on_chain_data: 链上数据
            validity_days: 分数有效期

        Returns:
            CreditScore
        """
        factors = []

        # 计算各因素得分
        factors.append(self._compute_account_age(on_chain_data))
        factors.append(self._compute_account_activity(on_chain_data))
        factors.append(self._compute_transaction_volume(on_chain_data))
        factors.append(self._compute_transaction_frequency(on_chain_data))
        factors.append(self._compute_lending_history(on_chain_data))
        factors.append(self._compute_repayment_record(on_chain_data))
        factors.append(self._compute_liquidation_history(on_chain_data))
        factors.append(self._compute_asset_diversity(on_chain_data))

        # 计算总分
        weighted_sum = sum(f.weighted_score for f in factors)
        total_weight = sum(f.weight for f in factors)

        # 将加权平均映射到300-850范围
        if total_weight > 0:
            normalized_average = weighted_sum / total_weight
            total_score = int(300 + (normalized_average / 100) * 550)
        else:
            total_score = 300

        total_score = max(300, min(850, total_score))

        # 生成属性标签
        attributes = self._generate_attributes(factors, on_chain_data)

        # 计算有效期
        valid_until = datetime.now() + timedelta(days=validity_days)

        # 创建评分承诺
        score_commitment = hashlib.sha256(
            address.lower().encode() +
            total_score.to_bytes(4, 'big') +
            secrets.token_bytes(16)
        ).digest()

        return CreditScore(
            score_id=secrets.token_hex(8),
            address=address,
            address_hash=b'',
            total_score=total_score,
            score_range=ScoreRange.from_score(total_score),
            factors=factors,
            attributes=attributes,
            valid_until=valid_until,
            score_commitment=score_commitment
        )

    def _compute_account_age(self, data: Dict[str, Any]) -> CreditFactor:
        """计算账户年龄得分"""
        # 账户年龄（天）
        age_days = data.get("account_age_days", 0)

        # 标准化：2年以上得满分
        if age_days >= 730:
            normalized = 100
        elif age_days >= 365:
            normalized = 70 + (age_days - 365) / 365 * 30
        elif age_days >= 90:
            normalized = 40 + (age_days - 90) / 275 * 30
        else:
            normalized = age_days / 90 * 40

        return CreditFactor(
            factor_type=CreditFactorType.ACCOUNT_AGE,
            name="Account Age",
            description="How long the account has been active",
            raw_value=age_days,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.ACCOUNT_AGE, 0.10)
        )

    def _compute_account_activity(self, data: Dict[str, Any]) -> CreditFactor:
        """计算账户活跃度得分"""
        # 最近30天活跃天数
        active_days = data.get("active_days_30d", 0)

        # 标准化：每周至少活跃3天得满分
        if active_days >= 20:
            normalized = 100
        elif active_days >= 10:
            normalized = 60 + (active_days - 10) / 10 * 40
        else:
            normalized = active_days / 10 * 60

        return CreditFactor(
            factor_type=CreditFactorType.ACCOUNT_ACTIVITY,
            name="Account Activity",
            description="Recent account activity level",
            raw_value=active_days,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.ACCOUNT_ACTIVITY, 0.08)
        )

    def _compute_transaction_volume(self, data: Dict[str, Any]) -> CreditFactor:
        """计算交易量得分"""
        # 总交易量（ETH）
        volume = data.get("total_volume_eth", 0)

        # 标准化：100 ETH以上得满分
        if volume >= 100:
            normalized = 100
        elif volume >= 10:
            normalized = 50 + (volume - 10) / 90 * 50
        elif volume >= 1:
            normalized = 20 + (volume - 1) / 9 * 30
        else:
            normalized = volume * 20

        return CreditFactor(
            factor_type=CreditFactorType.TRANSACTION_VOLUME,
            name="Transaction Volume",
            description="Total transaction volume",
            raw_value=volume,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.TRANSACTION_VOLUME, 0.12)
        )

    def _compute_transaction_frequency(self, data: Dict[str, Any]) -> CreditFactor:
        """计算交易频率得分"""
        # 月均交易次数
        monthly_txs = data.get("monthly_transactions", 0)

        # 标准化：50次以上得满分
        if monthly_txs >= 50:
            normalized = 100
        elif monthly_txs >= 20:
            normalized = 60 + (monthly_txs - 20) / 30 * 40
        elif monthly_txs >= 5:
            normalized = 30 + (monthly_txs - 5) / 15 * 30
        else:
            normalized = monthly_txs / 5 * 30

        return CreditFactor(
            factor_type=CreditFactorType.TRANSACTION_FREQUENCY,
            name="Transaction Frequency",
            description="Monthly transaction frequency",
            raw_value=monthly_txs,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.TRANSACTION_FREQUENCY, 0.08)
        )

    def _compute_lending_history(self, data: Dict[str, Any]) -> CreditFactor:
        """计算借贷历史得分"""
        # 借贷次数
        loan_count = data.get("loan_count", 0)
        # 成功还款次数
        repaid_count = data.get("loans_repaid", 0)

        if loan_count == 0:
            # 无借贷历史，给中等分
            normalized = 50
        else:
            # 还款率
            repay_rate = repaid_count / loan_count
            normalized = repay_rate * 100

        return CreditFactor(
            factor_type=CreditFactorType.LENDING_HISTORY,
            name="Lending History",
            description="DeFi lending participation history",
            raw_value=loan_count,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.LENDING_HISTORY, 0.15)
        )

    def _compute_repayment_record(self, data: Dict[str, Any]) -> CreditFactor:
        """计算还款记录得分"""
        # 按时还款率
        on_time_rate = data.get("on_time_repayment_rate", 1.0)
        # 逾期次数
        late_payments = data.get("late_payments", 0)

        # 基础分
        normalized = on_time_rate * 100

        # 逾期惩罚
        penalty = min(late_payments * 10, 50)
        normalized = max(0, normalized - penalty)

        return CreditFactor(
            factor_type=CreditFactorType.REPAYMENT_RECORD,
            name="Repayment Record",
            description="Loan repayment history",
            raw_value=on_time_rate,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.REPAYMENT_RECORD, 0.18)
        )

    def _compute_liquidation_history(self, data: Dict[str, Any]) -> CreditFactor:
        """计算清算历史得分"""
        # 清算次数
        liquidations = data.get("liquidation_count", 0)

        # 无清算满分，每次清算扣20分
        normalized = max(0, 100 - liquidations * 20)

        return CreditFactor(
            factor_type=CreditFactorType.LIQUIDATION_HISTORY,
            name="Liquidation History",
            description="DeFi liquidation history",
            raw_value=liquidations,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.LIQUIDATION_HISTORY, 0.10)
        )

    def _compute_asset_diversity(self, data: Dict[str, Any]) -> CreditFactor:
        """计算资产多样性得分"""
        # 持有代币种类
        token_count = data.get("unique_tokens", 0)

        # 标准化：10种以上满分
        if token_count >= 10:
            normalized = 100
        elif token_count >= 5:
            normalized = 50 + (token_count - 5) / 5 * 50
        else:
            normalized = token_count / 5 * 50

        return CreditFactor(
            factor_type=CreditFactorType.ASSET_DIVERSITY,
            name="Asset Diversity",
            description="Diversity of token holdings",
            raw_value=token_count,
            normalized_score=normalized,
            weight=self.weights.get(CreditFactorType.ASSET_DIVERSITY, 0.05)
        )

    def _generate_attributes(
        self,
        factors: List[CreditFactor],
        data: Dict[str, Any]
    ) -> Set[str]:
        """生成信用属性标签"""
        attributes = set()

        # 基于因素得分
        for f in factors:
            if f.factor_type == CreditFactorType.REPAYMENT_RECORD and f.normalized_score >= 95:
                attributes.add("perfect_repayment")
            if f.factor_type == CreditFactorType.LIQUIDATION_HISTORY and f.normalized_score == 100:
                attributes.add("no_liquidation")
            if f.factor_type == CreditFactorType.ACCOUNT_AGE and f.raw_value >= 365:
                attributes.add("veteran_user")
            if f.factor_type == CreditFactorType.TRANSACTION_VOLUME and f.raw_value >= 100:
                attributes.add("high_volume_trader")

        # 基于原始数据
        if data.get("has_ens", False):
            attributes.add("ens_holder")
        if data.get("dao_memberships", 0) > 0:
            attributes.add("dao_member")
        if data.get("nft_count", 0) >= 10:
            attributes.add("nft_collector")
        if data.get("defi_protocols_used", 0) >= 5:
            attributes.add("defi_power_user")

        return attributes

    def update_weights(self, new_weights: Dict[CreditFactorType, float]) -> None:
        """更新因素权重"""
        self.weights.update(new_weights)

        # 确保权重总和为1
        total = sum(self.weights.values())
        if total != 1.0:
            for k in self.weights:
                self.weights[k] /= total
