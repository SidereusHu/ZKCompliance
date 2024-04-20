"""
ZK-KYC 探索脚本

Phase 2: 零知识身份验证演示

演示如何使用ZK-KYC系统进行隐私保护的身份验证。
"""

from datetime import date, datetime
from typing import Optional
import secrets

# 导入KYC模块
from src.kyc import (
    # 凭证系统
    Credential,
    CredentialSchema,
    CredentialAttribute,
    AttributeType,
    IDENTITY_SCHEMA,
    AGE_SCHEMA,
    create_credential,
    compute_age,
    # 年龄证明
    AgeProver,
    AgeVerifier,
    AgeCredential,
    AgeProof,
    create_test_age_credential,
    # 成员身份证明
    MembershipProver,
    MembershipVerifier,
    MembershipProof,
    SetCommitment,
    COMPLIANT_COUNTRIES,
    OFAC_SANCTIONED_COUNTRIES,
    create_nationality_whitelist,
    create_nationality_blacklist,
    # 凭证签发
    CredentialIssuer,
    IssuerKeyPair,
    IssuanceRequest,
    IssuanceResponse,
    # 验证器
    KYCVerifier,
    VerificationRequest,
    VerificationResult,
    VerificationPolicy,
    VerificationRequirement,
    RequirementType,
    BASIC_KYC_POLICY,
    FINANCIAL_KYC_POLICY,
)


def separator(title: str) -> None:
    """打印分隔符"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def demo_age_proof() -> None:
    """演示年龄证明"""
    separator("年龄证明演示 (Age Proof)")

    # 创建年龄证明器
    prover = AgeProver()
    verifier = AgeVerifier()

    # 场景1: 证明年龄 >= 18（成年人验证）
    print("\n【场景1】证明用户年龄 >= 18岁")
    print("-" * 40)

    # 创建年龄凭证（出生日期：2000年5月15日）
    birth_date = date(2000, 5, 15)
    credential = prover.create_age_credential(birth_date)

    print(f"凭证ID: {credential.credential_id}")
    print(f"出生日期: {credential.birth_date} (私密，不会泄露)")
    print(f"当前年龄: {credential.get_age()} 岁")

    # 生成年龄证明
    print("\n生成零知识证明...")
    proof = prover.prove_age_gte(credential, threshold_age=18)

    print(f"证明类型: {proof.claim_type}")
    print(f"阈值年龄: {proof.threshold_age}")
    print(f"参考日期: {proof.reference_date}")
    print(f"承诺点: ({proof.birth_date_commitment.x.value % 10**10}..., ...)")

    # 验证证明
    print("\n验证证明...")
    is_valid = verifier.verify_age_gte(proof, expected_threshold=18)
    print(f"验证结果: {'✓ 通过' if is_valid else '✗ 失败'}")

    # 场景2: 证明年龄在范围内
    print("\n【场景2】证明年龄在 21-65 岁范围内")
    print("-" * 40)

    # 创建另一个凭证（35岁用户）
    birth_date_2 = date(1989, 3, 10)
    credential_2 = prover.create_age_credential(birth_date_2)

    print(f"用户年龄: {credential_2.get_age()} 岁")

    range_proof = prover.prove_age_in_range(credential_2, min_age=21, max_age=65)
    is_valid_range = verifier.verify_age_in_range(range_proof, min_age=21, max_age=65)
    print(f"范围验证结果: {'✓ 通过' if is_valid_range else '✗ 失败'}")

    # 场景3: 未成年人无法证明
    print("\n【场景3】未成年人尝试证明年龄 >= 18")
    print("-" * 40)

    minor_birth = date(2015, 1, 1)
    minor_credential = prover.create_age_credential(minor_birth)
    print(f"用户年龄: {minor_credential.get_age()} 岁")

    try:
        minor_proof = prover.prove_age_gte(minor_credential, threshold_age=18)
        print("生成证明成功（不应该发生）")
    except ValueError as e:
        print(f"无法生成证明: {e}")
        print("✓ 系统正确拒绝了未成年人的证明请求")


def demo_membership_proof() -> None:
    """演示国籍/成员身份证明"""
    separator("国籍成员身份证明演示 (Membership Proof)")

    prover = MembershipProver()
    verifier = MembershipVerifier()

    # 创建合规国家白名单
    print("\n【创建国籍白名单】")
    print("-" * 40)

    whitelist_countries = ["US", "GB", "DE", "FR", "JP", "CN", "SG", "HK"]
    print(f"白名单国家: {whitelist_countries}")

    set_commitment, merkle_tree = prover.create_set_commitment(
        values=whitelist_countries,
        metadata={"type": "nationality_whitelist", "version": "1.0"}
    )

    print(f"集合ID: {set_commitment.set_id}")
    print(f"Merkle根: {set_commitment.root.hex()[:32]}...")
    print(f"集合大小: {set_commitment.size}")

    # 场景1: 证明国籍在白名单中
    print("\n【场景1】证明国籍在白名单中（CN）")
    print("-" * 40)

    user_nationality = "CN"
    membership_proof = prover.prove_membership(
        value=user_nationality,
        merkle_tree=merkle_tree,
        set_commitment=set_commitment,
    )

    print(f"证明类型: {membership_proof.proof_type}")
    print(f"Merkle路径长度: {len(membership_proof.merkle_path)}")

    # 验证
    is_member = verifier.verify_membership(
        membership_proof,
        expected_root=set_commitment.root,
    )
    print(f"成员验证结果: {'✓ 用户国籍在白名单中' if is_member else '✗ 验证失败'}")

    # 场景2: 证明不在黑名单中
    print("\n【场景2】证明国籍不在OFAC制裁名单中")
    print("-" * 40)

    blacklist = OFAC_SANCTIONED_COUNTRIES
    print(f"黑名单国家: {blacklist}")

    user_country = "JP"
    print(f"用户国籍: {user_country}")

    non_membership_proof = prover.prove_non_membership(
        value=user_country,
        excluded_set=blacklist,
        set_commitment=set_commitment,
    )

    is_not_member = verifier.verify_non_membership(non_membership_proof)
    print(f"非成员验证结果: {'✓ 用户国籍不在黑名单中' if is_not_member else '✗ 验证失败'}")

    # 场景3: 受制裁国家用户无法通过
    print("\n【场景3】受制裁国家用户尝试证明不在黑名单")
    print("-" * 40)

    sanctioned_user = "KP"  # 朝鲜
    print(f"用户国籍: {sanctioned_user}")

    try:
        bad_proof = prover.prove_non_membership(
            value=sanctioned_user,
            excluded_set=blacklist,
            set_commitment=set_commitment,
        )
        print("生成证明成功（不应该发生）")
    except ValueError as e:
        print(f"无法生成证明: {e}")
        print("✓ 系统正确拒绝了受制裁国家用户的证明请求")


def demo_credential_issuance() -> None:
    """演示凭证签发流程"""
    separator("凭证签发流程演示 (Credential Issuance)")

    # 创建发行者
    print("\n【初始化发行者】")
    print("-" * 40)

    issuer = CredentialIssuer(
        issuer_id="gov-kyc-issuer-001",
        supported_schemas=[IDENTITY_SCHEMA, AGE_SCHEMA],
    )

    # 生成密钥对
    key_pair = issuer.generate_key_pair()
    print(f"发行者ID: {issuer.issuer_id}")
    print(f"公钥 X: {key_pair.public_key.x.value % 10**15}...")
    print(f"支持的模式: {list(issuer.supported_schemas.keys())}")

    # 签发身份凭证
    print("\n【签发身份凭证】")
    print("-" * 40)

    issuance_request = IssuanceRequest(
        request_id=secrets.token_hex(8),
        schema_id="identity-v1",
        attributes={
            "full_name": "Alice Zhang",
            "birth_date": "1995-06-20",
            "nationality": "CN",
            "document_number": "A12345678",
            "document_type": "passport",
        },
        metadata={"holder_id": "user_alice_001"},
    )

    print(f"请求ID: {issuance_request.request_id}")
    print(f"模式: {issuance_request.schema_id}")
    print(f"属性: {list(issuance_request.attributes.keys())}")

    response = issuer.process_issuance_request(issuance_request)

    if response.success:
        print(f"\n✓ 凭证签发成功!")
        print(f"凭证ID: {response.credential.credential.credential_id}")
        print(f"签名类型: {response.credential.signature_type}")
        print(f"签名长度: {len(response.credential.signature)} bytes")
        print(f"属性数量: {len(response.credential.credential.attributes)}")
    else:
        print(f"✗ 签发失败: {response.error_message}")

    # 尝试签发缺少必需属性的凭证
    print("\n【尝试签发不完整凭证】")
    print("-" * 40)

    incomplete_request = IssuanceRequest(
        request_id=secrets.token_hex(8),
        schema_id="identity-v1",
        attributes={
            "full_name": "Bob Smith",
            # 缺少 birth_date 和 nationality
        },
    )

    incomplete_response = issuer.process_issuance_request(incomplete_request)
    if not incomplete_response.success:
        print(f"✓ 正确拒绝: {incomplete_response.error_message}")

    # 凭证撤销
    print("\n【凭证撤销】")
    print("-" * 40)

    if response.success:
        cred_id = response.credential.credential.credential_id
        revoked = issuer.revoke_credential(cred_id, reason="Identity fraud detected")
        print(f"撤销凭证 {cred_id[:16]}...")
        print(f"撤销结果: {'✓ 成功' if revoked else '✗ 失败'}")
        print(f"是否已撤销: {issuer.is_revoked(cred_id)}")


def demo_kyc_verification() -> None:
    """演示KYC验证流程"""
    separator("KYC验证流程演示 (Full KYC Verification)")

    # 初始化组件
    age_prover = AgeProver()
    membership_prover = MembershipProver()
    kyc_verifier = KYCVerifier()

    # 注册验证策略
    print("\n【注册验证策略】")
    print("-" * 40)

    kyc_verifier.register_policy(BASIC_KYC_POLICY)
    kyc_verifier.register_policy(FINANCIAL_KYC_POLICY)

    print(f"已注册策略: {list(kyc_verifier.policies.keys())}")

    # 创建合规国家白名单
    whitelist_commitment, whitelist_tree = membership_prover.create_set_commitment(
        values=sorted(list(COMPLIANT_COUNTRIES)),
        metadata={"type": "compliant_countries"}
    )
    kyc_verifier.register_set_commitment("compliant-countries", whitelist_commitment)

    # 场景1: 基本KYC验证
    print("\n【场景1】基本KYC验证（年龄 >= 18）")
    print("-" * 40)

    # 用户创建年龄凭证和证明
    user_birth = date(1998, 8, 25)
    user_credential = age_prover.create_age_credential(user_birth)
    age_proof = age_prover.prove_age_gte(user_credential, threshold_age=18)

    print(f"用户年龄: {user_credential.get_age()}")

    # 提交验证请求
    verification_request = VerificationRequest(
        request_id=secrets.token_hex(8),
        policy_id="basic-kyc",
        proofs={"age_proof": age_proof},
    )

    result = kyc_verifier.verify(verification_request)

    print(f"验证策略: {result.policy_id}")
    print(f"验证状态: {result.status.value}")
    print(f"总体结果: {'✓ 通过' if result.all_passed else '✗ 未通过'}")

    for req_result in result.requirement_results:
        status = "✓" if req_result.passed else "✗"
        print(f"  {status} {req_result.requirement_type.value}: {req_result.details}")

    # 场景2: 金融服务KYC验证
    print("\n【场景2】金融服务KYC验证")
    print("-" * 40)

    # 创建国籍证明
    user_nationality = "CN"
    nationality_proof = membership_prover.prove_membership(
        value=user_nationality,
        merkle_tree=whitelist_tree,
        set_commitment=whitelist_commitment,
    )

    # 创建非成员证明（不在OFAC名单）
    non_sanctioned_proof = membership_prover.prove_non_membership(
        value=user_nationality,
        excluded_set=OFAC_SANCTIONED_COUNTRIES,
        set_commitment=whitelist_commitment,
    )

    financial_request = VerificationRequest(
        request_id=secrets.token_hex(8),
        policy_id="financial-kyc",
        proofs={
            "age_proof": age_proof,
            "membership_proof": nationality_proof,
            "non_membership_proof": non_sanctioned_proof,
        },
    )

    financial_result = kyc_verifier.verify(financial_request)

    print(f"验证策略: {financial_result.policy_id}")
    print(f"验证状态: {financial_result.status.value}")

    for req_result in financial_result.requirement_results:
        status = "✓" if req_result.passed else "✗"
        error = f" - {req_result.error_message}" if req_result.error_message else ""
        print(f"  {status} {req_result.requirement_type.value}{error}")

    # 场景3: 未成年人KYC失败
    print("\n【场景3】未成年人KYC验证（预期失败）")
    print("-" * 40)

    minor_birth = date(2010, 3, 15)
    minor_credential = age_prover.create_age_credential(minor_birth)
    print(f"用户年龄: {minor_credential.get_age()}")

    try:
        minor_proof = age_prover.prove_age_gte(minor_credential, threshold_age=18)
        minor_request = VerificationRequest(
            request_id=secrets.token_hex(8),
            policy_id="basic-kyc",
            proofs={"age_proof": minor_proof},
        )
        minor_result = kyc_verifier.verify(minor_request)
    except ValueError as e:
        print(f"无法生成证明: {e}")
        print("✓ 系统正确阻止了未成年人通过KYC")


def demo_privacy_features() -> None:
    """演示隐私保护特性"""
    separator("隐私保护特性演示")

    print("\n【零知识证明的隐私保护】")
    print("-" * 40)

    prover = AgeProver()

    # 创建用户凭证
    actual_birth = date(1990, 7, 4)
    credential = prover.create_age_credential(actual_birth)

    print(f"用户实际出生日期: {actual_birth}")
    print(f"用户实际年龄: {credential.get_age()}")

    # 生成证明
    proof = prover.prove_age_gte(credential, threshold_age=18)

    print("\n【证明中泄露的信息】")
    print("-" * 40)

    proof_dict = proof.to_dict()

    print(f"声明类型: {proof_dict['claim_type']} (公开)")
    print(f"阈值年龄: {proof_dict['threshold_age']} (公开)")
    print(f"参考日期: {proof_dict['reference_date']} (公开)")
    print(f"承诺值: {proof_dict['commitment']} (密码学承诺，无法反推)")
    print(f"挑战值: {proof_dict['challenge'][:20]}... (随机)")
    print(f"响应值: {proof_dict['response'][:20]}... (计算值)")

    print("\n【证明中未泄露的信息】")
    print("-" * 40)

    print(f"✓ 实际出生日期: {actual_birth} (隐藏)")
    print(f"✓ 实际年龄: {credential.get_age()} (隐藏)")
    print(f"✓ 盲因子: *** (隐藏)")
    print(f"✓ 原始凭证内容 (隐藏)")

    print("\n【密码学保证】")
    print("-" * 40)

    print("1. 完备性: 如果声明为真，诚实的证明者总能生成有效证明")
    print("2. 可靠性: 如果声明为假，不诚实的证明者无法生成有效证明")
    print("3. 零知识: 验证者除了声明为真外，不能获取任何其他信息")


def main() -> None:
    """主函数"""
    print("\n" + "=" * 60)
    print("  ZK-KYC 零知识身份验证系统")
    print("  Phase 2 演示")
    print("=" * 60)

    print("\n本演示展示如何使用零知识证明实现隐私保护的KYC验证。")
    print("用户可以证明自己满足某些条件（如年龄、国籍），")
    print("而无需泄露具体的个人信息。")

    # 运行各个演示
    demo_age_proof()
    demo_membership_proof()
    demo_credential_issuance()
    demo_kyc_verification()
    demo_privacy_features()

    # 总结
    separator("演示完成")

    print("\n【Phase 2 实现的功能】")
    print("-" * 40)
    print("✓ 年龄证明: 证明年龄 >= 阈值，不泄露出生日期")
    print("✓ 范围证明: 证明年龄在某个范围内")
    print("✓ 成员身份证明: 证明国籍在白名单中")
    print("✓ 非成员身份证明: 证明国籍不在黑名单中")
    print("✓ 凭证签发: 支持BLS签名的凭证签发")
    print("✓ 凭证撤销: 支持凭证撤销机制")
    print("✓ 验证策略: 可配置的KYC验证策略")
    print("✓ 隐私保护: 完整的零知识隐私保护")

    print("\n【应用场景】")
    print("-" * 40)
    print("• DeFi协议: 合规用户准入验证")
    print("• NFT平台: 年龄限制内容验证")
    print("• 交易所: FATF合规检查")
    print("• DAO治理: 匿名资格验证")
    print("• 借贷协议: 信用资格验证")


if __name__ == "__main__":
    main()
