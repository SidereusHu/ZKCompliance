"""
可验证凭证数据模型

基于W3C Verifiable Credentials标准设计的ZK友好凭证系统
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, date
from typing import Dict, List, Optional, Any, Union
from enum import Enum
import hashlib
import json
import secrets


class AttributeType(Enum):
    """属性类型"""
    STRING = "string"
    INTEGER = "integer"
    DATE = "date"
    BOOLEAN = "boolean"
    BYTES = "bytes"
    ENUM = "enum"  # 枚举类型（用于国籍等）


class CredentialStatus(Enum):
    """凭证状态"""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


@dataclass
class CredentialAttribute:
    """凭证属性

    表示凭证中的单个属性，如姓名、出生日期等。
    """
    name: str
    value: Any
    attr_type: AttributeType
    # 是否可以选择性披露
    disclosable: bool = True
    # 属性的承诺值（用于ZK证明）
    commitment: Optional[bytes] = None
    # 用于承诺的随机数
    blinding_factor: Optional[int] = None

    def to_field_element(self, field_prime: int) -> int:
        """转换为有限域元素"""
        if self.attr_type == AttributeType.INTEGER:
            return int(self.value) % field_prime
        elif self.attr_type == AttributeType.DATE:
            # 日期转换为自1970年以来的天数
            if isinstance(self.value, date):
                epoch = date(1970, 1, 1)
                delta = self.value - epoch
                return delta.days % field_prime
            elif isinstance(self.value, str):
                d = date.fromisoformat(self.value)
                epoch = date(1970, 1, 1)
                delta = d - epoch
                return delta.days % field_prime
        elif self.attr_type == AttributeType.BOOLEAN:
            return 1 if self.value else 0
        elif self.attr_type == AttributeType.STRING:
            # 字符串哈希到域元素
            h = hashlib.sha256(self.value.encode()).digest()
            return int.from_bytes(h, 'big') % field_prime
        elif self.attr_type == AttributeType.BYTES:
            return int.from_bytes(self.value, 'big') % field_prime
        elif self.attr_type == AttributeType.ENUM:
            # 枚举值使用其索引
            if isinstance(self.value, int):
                return self.value % field_prime
            # 如果是字符串，哈希它
            h = hashlib.sha256(str(self.value).encode()).digest()
            return int.from_bytes(h, 'big') % field_prime

        raise ValueError(f"Unsupported attribute type: {self.attr_type}")

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（不包含敏感信息）"""
        return {
            "name": self.name,
            "type": self.attr_type.value,
            "disclosable": self.disclosable,
            "has_commitment": self.commitment is not None,
        }


@dataclass
class CredentialSchema:
    """凭证模式

    定义凭证的结构和属性类型。
    """
    schema_id: str
    name: str
    version: str
    attributes: List[Dict[str, Any]]  # [{"name": "...", "type": "...", "required": bool}]
    issuer_id: Optional[str] = None
    description: str = ""

    def validate_credential(self, credential: "Credential") -> bool:
        """验证凭证是否符合模式"""
        required_attrs = {
            attr["name"] for attr in self.attributes if attr.get("required", False)
        }
        credential_attrs = {attr.name for attr in credential.attributes}

        # 检查必需属性
        if not required_attrs.issubset(credential_attrs):
            return False

        # 检查属性类型
        attr_types = {attr["name"]: attr["type"] for attr in self.attributes}
        for attr in credential.attributes:
            if attr.name in attr_types:
                if attr.attr_type.value != attr_types[attr.name]:
                    return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "name": self.name,
            "version": self.version,
            "attributes": self.attributes,
            "issuer_id": self.issuer_id,
            "description": self.description,
        }


@dataclass
class Credential:
    """可验证凭证

    包含用户的身份属性，可用于生成零知识证明。
    """
    credential_id: str
    schema_id: str
    holder_id: str  # 持有者标识（通常是公钥哈希）
    attributes: List[CredentialAttribute]
    issued_at: dt = dc_field(default_factory=dt.now)
    expires_at: Optional[dt] = None
    status: CredentialStatus = CredentialStatus.ACTIVE
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def get_attribute(self, name: str) -> Optional[CredentialAttribute]:
        """获取指定属性"""
        for attr in self.attributes:
            if attr.name == name:
                return attr
        return None

    def get_attribute_value(self, name: str) -> Optional[Any]:
        """获取属性值"""
        attr = self.get_attribute(name)
        return attr.value if attr else None

    def is_valid(self) -> bool:
        """检查凭证是否有效"""
        if self.status != CredentialStatus.ACTIVE:
            return False
        if self.expires_at and dt.now() > self.expires_at:
            return False
        return True

    def compute_hash(self) -> bytes:
        """计算凭证哈希"""
        data = {
            "credential_id": self.credential_id,
            "schema_id": self.schema_id,
            "holder_id": self.holder_id,
            "attributes": [
                {"name": a.name, "value": str(a.value), "type": a.attr_type.value}
                for a in self.attributes
            ],
            "issued_at": self.issued_at.isoformat(),
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).digest()

    def to_dict(self, include_values: bool = False) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "credential_id": self.credential_id,
            "schema_id": self.schema_id,
            "holder_id": self.holder_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
        }
        if include_values:
            result["attributes"] = [
                {"name": a.name, "value": a.value, "type": a.attr_type.value}
                for a in self.attributes
            ]
        else:
            result["attributes"] = [a.to_dict() for a in self.attributes]
        return result


@dataclass
class SignedCredential:
    """签名凭证

    包含发行者签名的凭证。
    """
    credential: Credential
    issuer_id: str
    signature: bytes
    signature_type: str = "BLS"  # BLS, ECDSA, etc.
    # 签名相关的公开参数
    public_params: Dict[str, Any] = dc_field(default_factory=dict)

    def verify_signature(self, issuer_public_key: Any) -> bool:
        """验证签名（具体实现取决于签名类型）"""
        # 简化实现
        credential_hash = self.credential.compute_hash()
        # 实际应使用对应的签名验证算法
        return len(self.signature) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "credential": self.credential.to_dict(),
            "issuer_id": self.issuer_id,
            "signature": self.signature.hex(),
            "signature_type": self.signature_type,
        }


# ============================================================
# 预定义凭证模式
# ============================================================

# 身份凭证模式
IDENTITY_SCHEMA = CredentialSchema(
    schema_id="identity-v1",
    name="Identity Credential",
    version="1.0",
    description="Basic identity credential with name, birthdate, and nationality",
    attributes=[
        {"name": "full_name", "type": "string", "required": True},
        {"name": "birth_date", "type": "date", "required": True},
        {"name": "nationality", "type": "enum", "required": True},
        {"name": "document_number", "type": "string", "required": False},
        {"name": "document_type", "type": "enum", "required": False},
    ]
)

# 年龄凭证模式
AGE_SCHEMA = CredentialSchema(
    schema_id="age-v1",
    name="Age Credential",
    version="1.0",
    description="Credential for age verification",
    attributes=[
        {"name": "birth_date", "type": "date", "required": True},
        {"name": "birth_year", "type": "integer", "required": False},
    ]
)

# 国籍凭证模式
NATIONALITY_SCHEMA = CredentialSchema(
    schema_id="nationality-v1",
    name="Nationality Credential",
    version="1.0",
    description="Credential for nationality/citizenship verification",
    attributes=[
        {"name": "nationality_code", "type": "string", "required": True},
        {"name": "nationality_name", "type": "string", "required": False},
        {"name": "is_citizen", "type": "boolean", "required": False},
    ]
)

# 地址凭证模式
ADDRESS_SCHEMA = CredentialSchema(
    schema_id="address-v1",
    name="Address Credential",
    version="1.0",
    description="Credential for address verification",
    attributes=[
        {"name": "country", "type": "string", "required": True},
        {"name": "region", "type": "string", "required": False},
        {"name": "city", "type": "string", "required": False},
        {"name": "postal_code", "type": "string", "required": False},
    ]
)


# ============================================================
# 辅助函数
# ============================================================

def create_credential(
    schema: CredentialSchema,
    holder_id: str,
    attributes: Dict[str, Any],
    expires_days: Optional[int] = 365
) -> Credential:
    """创建凭证的便捷函数"""
    from datetime import timedelta

    # 查找属性类型
    attr_types = {attr["name"]: attr["type"] for attr in schema.attributes}

    cred_attrs = []
    for name, value in attributes.items():
        attr_type_str = attr_types.get(name, "string")
        attr_type = AttributeType(attr_type_str)
        cred_attrs.append(CredentialAttribute(
            name=name,
            value=value,
            attr_type=attr_type,
        ))

    expires_at = None
    if expires_days:
        expires_at = dt.now() + timedelta(days=expires_days)

    return Credential(
        credential_id=secrets.token_hex(16),
        schema_id=schema.schema_id,
        holder_id=holder_id,
        attributes=cred_attrs,
        expires_at=expires_at,
    )


def compute_age(birth_date: date, reference_date: Optional[date] = None) -> int:
    """计算年龄"""
    if reference_date is None:
        reference_date = date.today()

    age = reference_date.year - birth_date.year

    # 检查是否已过生日
    if (reference_date.month, reference_date.day) < (birth_date.month, birth_date.day):
        age -= 1

    return age


def date_to_days_since_epoch(d: date) -> int:
    """将日期转换为自1970-01-01以来的天数"""
    epoch = date(1970, 1, 1)
    return (d - epoch).days


def days_since_epoch_to_date(days: int) -> date:
    """将天数转换为日期"""
    from datetime import timedelta
    epoch = date(1970, 1, 1)
    return epoch + timedelta(days=days)
