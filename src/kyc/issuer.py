"""
凭证签发系统

实现凭证的签发和管理:
- 发行者密钥管理
- 凭证签发流程
- 盲签名支持（隐私保护）
- 凭证撤销
"""

from dataclasses import dataclass, field as dc_field
from datetime import datetime as dt, date, timedelta
from typing import Optional, List, Dict, Any, Tuple
import hashlib
import secrets
import json

from src.zkp.primitives import (
    EllipticCurve,
    Point,
    FiniteField,
    BN128,
)
from src.zkp.commitment import PedersenCommitment
from src.kyc.credential import (
    Credential,
    CredentialSchema,
    CredentialAttribute,
    AttributeType,
    CredentialStatus,
    SignedCredential,
)


@dataclass
class IssuerKeyPair:
    """发行者密钥对

    包含签名所需的公私钥。
    """
    # 私钥（标量）
    private_key: int
    # 公钥（椭圆曲线点）
    public_key: Point
    # 发行者ID
    issuer_id: str
    # 创建时间
    created_at: dt = dc_field(default_factory=dt.now)
    # 密钥用途
    key_usage: str = "credential_signing"

    def to_public_dict(self) -> Dict[str, Any]:
        """导出公开信息（不含私钥）"""
        return {
            "issuer_id": self.issuer_id,
            "public_key": {
                "x": str(self.public_key.x.value),
                "y": str(self.public_key.y.value),
            },
            "created_at": self.created_at.isoformat(),
            "key_usage": self.key_usage,
        }


@dataclass
class IssuanceRequest:
    """凭证签发请求

    用户向发行者提交的签发请求。
    """
    # 请求ID
    request_id: str
    # 请求的凭证模式
    schema_id: str
    # 用户提供的属性（可能是承诺形式）
    attributes: Dict[str, Any]
    # 用户的盲因子承诺（用于盲签名）
    blinding_commitment: Optional[Point] = None
    # 请求时间
    requested_at: dt = dc_field(default_factory=dt.now)
    # 元数据
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def __post_init__(self):
        if not self.request_id:
            self.request_id = secrets.token_hex(16)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "schema_id": self.schema_id,
            "attributes": self.attributes,
            "requested_at": self.requested_at.isoformat(),
        }


@dataclass
class IssuanceResponse:
    """凭证签发响应

    发行者对签发请求的响应。
    """
    # 请求ID
    request_id: str
    # 是否成功
    success: bool
    # 签发的凭证（如果成功）
    credential: Optional[SignedCredential] = None
    # 错误信息（如果失败）
    error_message: Optional[str] = None
    # 响应时间
    responded_at: dt = dc_field(default_factory=dt.now)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "request_id": self.request_id,
            "success": self.success,
            "responded_at": self.responded_at.isoformat(),
        }
        if self.credential:
            result["credential"] = self.credential.to_dict()
        if self.error_message:
            result["error_message"] = self.error_message
        return result


class CredentialIssuer:
    """凭证发行者

    负责签发和管理可验证凭证。
    """

    def __init__(
        self,
        issuer_id: str,
        curve: Optional[EllipticCurve] = None,
        supported_schemas: Optional[List[CredentialSchema]] = None,
    ):
        self.issuer_id = issuer_id
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

        # 支持的凭证模式
        self.supported_schemas: Dict[str, CredentialSchema] = {}
        if supported_schemas:
            for schema in supported_schemas:
                self.supported_schemas[schema.schema_id] = schema

        # 密钥管理
        self.key_pair: Optional[IssuerKeyPair] = None

        # 已签发凭证跟踪
        self.issued_credentials: Dict[str, SignedCredential] = {}

        # 撤销列表
        self.revocation_list: Dict[str, dt] = {}

    def generate_key_pair(self) -> IssuerKeyPair:
        """生成发行者密钥对"""
        private_key = self.curve.random_scalar()
        public_key = private_key * self.curve.generator

        self.key_pair = IssuerKeyPair(
            private_key=private_key,
            public_key=public_key,
            issuer_id=self.issuer_id,
        )
        return self.key_pair

    def load_key_pair(self, private_key: int, public_key: Point) -> IssuerKeyPair:
        """加载已有密钥对"""
        self.key_pair = IssuerKeyPair(
            private_key=private_key,
            public_key=public_key,
            issuer_id=self.issuer_id,
        )
        return self.key_pair

    def add_schema(self, schema: CredentialSchema) -> None:
        """添加支持的凭证模式"""
        self.supported_schemas[schema.schema_id] = schema

    def process_issuance_request(
        self,
        request: IssuanceRequest,
        verify_attributes: bool = True,
    ) -> IssuanceResponse:
        """处理签发请求

        Args:
            request: 签发请求
            verify_attributes: 是否验证属性（生产环境应开启）

        Returns:
            IssuanceResponse
        """
        if self.key_pair is None:
            return IssuanceResponse(
                request_id=request.request_id,
                success=False,
                error_message="Issuer key pair not initialized",
            )

        # 检查模式是否支持
        if request.schema_id not in self.supported_schemas:
            return IssuanceResponse(
                request_id=request.request_id,
                success=False,
                error_message=f"Unsupported schema: {request.schema_id}",
            )

        schema = self.supported_schemas[request.schema_id]

        # 验证必需属性
        if verify_attributes:
            required_attrs = {
                attr["name"] for attr in schema.attributes
                if attr.get("required", False)
            }
            provided_attrs = set(request.attributes.keys())

            if not required_attrs.issubset(provided_attrs):
                missing = required_attrs - provided_attrs
                return IssuanceResponse(
                    request_id=request.request_id,
                    success=False,
                    error_message=f"Missing required attributes: {missing}",
                )

        # 创建凭证
        try:
            credential = self._create_credential(request, schema)
            signed_credential = self._sign_credential(credential)

            # 记录签发
            self.issued_credentials[credential.credential_id] = signed_credential

            return IssuanceResponse(
                request_id=request.request_id,
                success=True,
                credential=signed_credential,
            )
        except Exception as e:
            return IssuanceResponse(
                request_id=request.request_id,
                success=False,
                error_message=str(e),
            )

    def _create_credential(
        self,
        request: IssuanceRequest,
        schema: CredentialSchema,
    ) -> Credential:
        """创建凭证"""
        # 查找属性类型
        attr_types = {attr["name"]: attr["type"] for attr in schema.attributes}

        # 创建属性列表
        cred_attrs = []
        for name, value in request.attributes.items():
            attr_type_str = attr_types.get(name, "string")
            attr_type = AttributeType(attr_type_str)

            # 为每个属性生成承诺
            blinding = self.curve.random_scalar()
            attr_value = self._convert_to_field_element(value, attr_type)
            commitment, _ = self.pedersen.commit(attr_value, blinding)

            cred_attrs.append(CredentialAttribute(
                name=name,
                value=value,
                attr_type=attr_type,
                commitment=commitment.to_bytes(),
                blinding_factor=blinding,
            ))

        # 计算holder_id（从请求元数据或生成）
        holder_id = request.metadata.get(
            "holder_id",
            hashlib.sha256(request.request_id.encode()).hexdigest()[:32]
        )

        return Credential(
            credential_id=secrets.token_hex(16),
            schema_id=schema.schema_id,
            holder_id=holder_id,
            attributes=cred_attrs,
            expires_at=dt.now() + timedelta(days=365),
        )

    def _convert_to_field_element(
        self,
        value: Any,
        attr_type: AttributeType
    ) -> int:
        """将值转换为有限域元素"""
        if attr_type == AttributeType.INTEGER:
            return int(value) % self.curve.n
        elif attr_type == AttributeType.DATE:
            if isinstance(value, date):
                epoch = date(1970, 1, 1)
                return (value - epoch).days % self.curve.n
            elif isinstance(value, str):
                d = date.fromisoformat(value)
                epoch = date(1970, 1, 1)
                return (d - epoch).days % self.curve.n
        elif attr_type == AttributeType.BOOLEAN:
            return 1 if value else 0
        elif attr_type == AttributeType.STRING:
            h = hashlib.sha256(str(value).encode()).digest()
            return int.from_bytes(h, 'big') % self.curve.n
        elif attr_type == AttributeType.ENUM:
            h = hashlib.sha256(str(value).encode()).digest()
            return int.from_bytes(h, 'big') % self.curve.n

        return 0

    def _sign_credential(self, credential: Credential) -> SignedCredential:
        """签名凭证

        使用BLS风格签名（简化实现）。
        """
        if self.key_pair is None:
            raise ValueError("Issuer key pair not initialized")

        # 计算凭证哈希
        credential_hash = credential.compute_hash()

        # 哈希到曲线点（简化）
        h = int.from_bytes(credential_hash, 'big') % self.curve.n
        message_point = h * self.curve.generator

        # BLS签名: σ = sk * H(m)
        signature_point = self.key_pair.private_key * message_point

        # 序列化签名
        signature = signature_point.to_bytes()

        return SignedCredential(
            credential=credential,
            issuer_id=self.issuer_id,
            signature=signature,
            signature_type="BLS",
            public_params={
                "curve": "BN128",
                "generator": {
                    "x": str(self.curve.generator.x.value),
                    "y": str(self.curve.generator.y.value),
                },
            },
        )

    def issue_blind_credential(
        self,
        request: IssuanceRequest,
    ) -> Tuple[SignedCredential, bytes]:
        """签发盲凭证

        用户提供盲化的属性，发行者签名后用户可以去盲化。
        这保护了用户的隐私，发行者不知道具体属性值。

        Returns:
            (SignedCredential, blind_signature) 元组
        """
        if self.key_pair is None:
            raise ValueError("Issuer key pair not initialized")

        if request.blinding_commitment is None:
            raise ValueError("Blinding commitment required for blind issuance")

        # 对盲化承诺签名
        blind_signature_point = self.key_pair.private_key * request.blinding_commitment

        # 创建占位凭证
        credential = Credential(
            credential_id=secrets.token_hex(16),
            schema_id=request.schema_id,
            holder_id="blind_holder",
            attributes=[],
        )

        signed = SignedCredential(
            credential=credential,
            issuer_id=self.issuer_id,
            signature=blind_signature_point.to_bytes(),
            signature_type="BLIND_BLS",
        )

        return signed, blind_signature_point.to_bytes()

    def revoke_credential(
        self,
        credential_id: str,
        reason: str = "revoked"
    ) -> bool:
        """撤销凭证

        Args:
            credential_id: 凭证ID
            reason: 撤销原因

        Returns:
            是否成功撤销
        """
        if credential_id not in self.issued_credentials:
            return False

        # 添加到撤销列表
        self.revocation_list[credential_id] = dt.now()

        # 更新凭证状态
        self.issued_credentials[credential_id].credential.status = CredentialStatus.REVOKED

        return True

    def is_revoked(self, credential_id: str) -> bool:
        """检查凭证是否已撤销"""
        return credential_id in self.revocation_list

    def get_revocation_list(self) -> Dict[str, str]:
        """获取撤销列表"""
        return {
            cid: timestamp.isoformat()
            for cid, timestamp in self.revocation_list.items()
        }

    def get_public_key(self) -> Optional[Point]:
        """获取发行者公钥"""
        if self.key_pair:
            return self.key_pair.public_key
        return None


class BlindCredentialHolder:
    """盲凭证持有者

    辅助用户进行盲签名协议。
    """

    def __init__(self, curve: Optional[EllipticCurve] = None):
        self.curve = curve or BN128
        self.pedersen = PedersenCommitment(self.curve)

    def create_blinding_request(
        self,
        attributes: Dict[str, Any],
        schema_id: str,
    ) -> Tuple[IssuanceRequest, int]:
        """创建盲化签发请求

        Args:
            attributes: 原始属性
            schema_id: 凭证模式ID

        Returns:
            (IssuanceRequest, blinding_factor) 元组
        """
        # 计算属性的哈希
        attr_hash = hashlib.sha256(
            json.dumps(attributes, sort_keys=True).encode()
        ).digest()
        attr_value = int.from_bytes(attr_hash, 'big') % self.curve.n

        # 生成盲因子
        blinding_factor = self.curve.random_scalar()

        # 创建盲化承诺
        commitment, _ = self.pedersen.commit(attr_value, blinding_factor)

        request = IssuanceRequest(
            request_id=secrets.token_hex(16),
            schema_id=schema_id,
            attributes={"blinded": True},
            blinding_commitment=commitment,
        )

        return request, blinding_factor

    def unblind_signature(
        self,
        blind_signature: bytes,
        blinding_factor: int,
        issuer_public_key: Point,
    ) -> bytes:
        """去盲签名

        Args:
            blind_signature: 盲签名
            blinding_factor: 盲因子
            issuer_public_key: 发行者公钥

        Returns:
            去盲后的签名
        """
        # 解析签名点
        # 简化: 直接使用盲签名
        # 完整实现需要: σ' = σ_blind - r * pk
        return blind_signature
