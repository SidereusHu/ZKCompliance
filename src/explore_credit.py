"""
Explore Credit Module - 信用模块探索

演示零知识信用评分系统的完整流程:
1. 计算信用分数
2. 生成信用证明
3. 验证信用证明
4. 应用信用策略
"""

from src.credit import (
    CreditScore,
    CreditScoreComputer,
    CreditProver,
    CreditVerifier,
    CreditPolicy,
    ScoreRange,
)
from src.credit.verifier import (
    BASIC_LOAN_POLICY,
    PRIME_LOAN_POLICY,
    INSTITUTIONAL_POLICY,
)


def main():
    print("=" * 60)
    print("ZK-Credit System - 零知识信用评分系统")
    print("=" * 60)

    # =========================================================
    # Part 1: 计算信用分数
    # =========================================================
    print("\n" + "=" * 60)
    print("Part 1: Credit Score Computation")
    print("=" * 60)

    # 创建评分计算器
    computer = CreditScoreComputer()

    # 模拟链上数据 - 优质用户
    excellent_user_data = {
        "account_age_days": 800,  # 2年以上
        "active_days_30d": 25,  # 高活跃度
        "total_volume_eth": 150,  # 高交易量
        "monthly_transactions": 60,  # 高频率
        "loan_count": 10,
        "loans_repaid": 10,  # 100%还款
        "on_time_repayment_rate": 1.0,
        "late_payments": 0,
        "liquidation_count": 0,  # 无清算
        "unique_tokens": 15,
        "has_ens": True,
        "dao_memberships": 3,
        "defi_protocols_used": 8,
    }

    # 计算分数
    excellent_score = computer.compute_score(
        address="0x742d35Cc6634C0532925a3b844Bc9e7595f8aB3C",
        on_chain_data=excellent_user_data,
        validity_days=30
    )

    print(f"\nExcellent User Score:")
    print(f"  Total Score: {excellent_score.total_score}")
    print(f"  Credit Range: {excellent_score.score_range.value}")
    print(f"  Attributes: {excellent_score.attributes}")

    print("\n  Factor Scores:")
    for factor in excellent_score.factors:
        print(f"    - {factor.name}: {factor.normalized_score:.1f} "
              f"(weight: {factor.weight:.2f}, weighted: {factor.weighted_score:.2f})")

    # 模拟链上数据 - 普通用户
    fair_user_data = {
        "account_age_days": 200,
        "active_days_30d": 10,
        "total_volume_eth": 5,
        "monthly_transactions": 15,
        "loan_count": 3,
        "loans_repaid": 2,
        "on_time_repayment_rate": 0.8,
        "late_payments": 1,
        "liquidation_count": 1,
        "unique_tokens": 4,
        "has_ens": False,
        "dao_memberships": 0,
        "defi_protocols_used": 2,
    }

    fair_score = computer.compute_score(
        address="0x8B3C5c7A5f9e4d2b1a0C6E8F7D9B4A3C2E1F0D9B",
        on_chain_data=fair_user_data,
        validity_days=30
    )

    print(f"\nFair User Score:")
    print(f"  Total Score: {fair_score.total_score}")
    print(f"  Credit Range: {fair_score.score_range.value}")
    print(f"  Attributes: {fair_score.attributes}")

    # =========================================================
    # Part 2: 生成信用证明
    # =========================================================
    print("\n" + "=" * 60)
    print("Part 2: Credit Proof Generation")
    print("=" * 60)

    prover = CreditProver(issuer="ZK-Credit Demo System")

    # 为优质用户生成证明
    print("\nGenerating proofs for Excellent User...")

    # 创建分数承诺
    score_commitment, blinding = prover.create_score_commitment(excellent_score)
    print(f"  Score commitment created on curve: {score_commitment.on_curve()}")

    # 生成阈值证明 - 证明分数 >= 700
    threshold_proof = prover.prove_threshold(
        excellent_score,
        threshold=700,
        score_commitment=score_commitment,
        blinding_factor=blinding,
        validity_hours=24
    )
    print(f"  Threshold proof (>= 700): {threshold_proof.proof_id}")

    # 生成属性证明
    attr_proofs = []
    for attr in ["perfect_repayment", "no_liquidation", "veteran_user"]:
        if attr in excellent_score.attributes:
            proof = prover.prove_attribute(excellent_score, attr)
            attr_proofs.append(proof)
            print(f"  Attribute proof ({attr}): {proof.proof_id}")

    # 生成综合信用证明
    credit_proof = prover.prove_credit(
        excellent_score,
        thresholds=[550, 650, 700, 750],
        attributes=list(excellent_score.attributes),
        disclose_range=True,
        validity_hours=24
    )

    print(f"\n  Composite Credit Proof: {credit_proof.proof_id}")
    print(f"  - Type: {credit_proof.proof_type.value}")
    print(f"  - Threshold proofs: {len(credit_proof.threshold_proofs)}")
    print(f"  - Attribute proofs: {len(credit_proof.attribute_proofs)}")
    print(f"  - Disclosed range: {credit_proof.disclosed_range.value if credit_proof.disclosed_range else 'None'}")

    # =========================================================
    # Part 3: 验证信用证明
    # =========================================================
    print("\n" + "=" * 60)
    print("Part 3: Credit Proof Verification")
    print("=" * 60)

    verifier = CreditVerifier()

    # 验证阈值证明
    print("\nVerifying threshold proof...")
    is_valid, msg = verifier.verify_threshold_proof(threshold_proof)
    print(f"  Result: {'VALID' if is_valid else 'INVALID'}")
    print(f"  Message: {msg}")

    # 验证属性证明
    print("\nVerifying attribute proofs...")
    for ap in attr_proofs:
        is_valid, msg = verifier.verify_attribute_proof(ap)
        print(f"  {ap.attribute}: {'VALID' if is_valid else 'INVALID'} - {msg}")

    # 验证综合证明
    print("\nVerifying composite credit proof...")
    result = verifier.verify_credit_proof(credit_proof)
    print(f"  Status: {result.status.value}")
    print(f"  Is Valid: {result.is_valid}")
    print(f"  Threshold results: {result.threshold_results}")
    print(f"  Attribute results: {result.attribute_results}")

    if result.errors:
        print(f"  Errors: {result.errors}")
    if result.warnings:
        print(f"  Warnings: {result.warnings}")

    # =========================================================
    # Part 4: 应用信用策略
    # =========================================================
    print("\n" + "=" * 60)
    print("Part 4: Credit Policy Evaluation")
    print("=" * 60)

    # 测试优质用户的证明
    print("\nEvaluating Excellent User against policies:")

    for policy in [BASIC_LOAN_POLICY, PRIME_LOAN_POLICY, INSTITUTIONAL_POLICY]:
        passes, reasons = verifier.check_policy(credit_proof, policy)
        status = "PASS" if passes else "FAIL"
        print(f"\n  {policy.name} ({policy.policy_id}):")
        print(f"    Status: {status}")
        print(f"    Min Score: {policy.min_score}")
        print(f"    Min Range: {policy.min_range.value if policy.min_range else 'None'}")
        print(f"    Required Attrs: {policy.required_attributes}")
        if not passes:
            for reason in reasons:
                print(f"    - {reason}")

    # 为普通用户生成证明并测试
    print("\n\nEvaluating Fair User against policies:")

    fair_credit_proof = prover.prove_credit(
        fair_score,
        thresholds=[450, 550],
        attributes=list(fair_score.attributes),
        disclose_range=True,
        validity_hours=24
    )

    for policy in [BASIC_LOAN_POLICY, PRIME_LOAN_POLICY]:
        passes, reasons = verifier.check_policy(fair_credit_proof, policy)
        status = "PASS" if passes else "FAIL"
        print(f"\n  {policy.name}:")
        print(f"    Status: {status}")
        if not passes:
            for reason in reasons:
                print(f"    - {reason}")

    # =========================================================
    # Part 5: 范围证明演示
    # =========================================================
    print("\n" + "=" * 60)
    print("Part 5: Range Proof Demonstration")
    print("=" * 60)

    # 证明分数在某个范围内
    range_proof = prover.prove_range(
        excellent_score,
        lower_bound=700,
        upper_bound=850,
        score_commitment=score_commitment,
        blinding_factor=blinding
    )

    print(f"\nRange Proof: {range_proof.proof_id}")
    print(f"  Proving score in [{range_proof.proof_data['lower_bound']}, "
          f"{range_proof.proof_data['upper_bound']}]")
    print(f"  Contains threshold proof: {len(range_proof.threshold_proofs) > 0}")

    # 验证范围证明
    range_result = verifier.verify_credit_proof(range_proof)
    print(f"  Verification: {range_result.status.value}")

    # =========================================================
    # Part 6: 自定义策略
    # =========================================================
    print("\n" + "=" * 60)
    print("Part 6: Custom Policy Definition")
    print("=" * 60)

    # 创建自定义策略
    custom_policy = CreditPolicy(
        policy_id="defi_whale",
        name="DeFi Whale Policy",
        description="For large DeFi participants with clean history",
        min_score=720,
        min_range=ScoreRange.GOOD,
        required_attributes={"no_liquidation", "defi_power_user"},
        forbidden_attributes={"suspicious_activity"}
    )

    print(f"\nCustom Policy: {custom_policy.name}")
    print(f"  Min Score: {custom_policy.min_score}")
    print(f"  Required: {custom_policy.required_attributes}")
    print(f"  Forbidden: {custom_policy.forbidden_attributes}")

    # 测试自定义策略
    passes, reasons = verifier.check_policy(credit_proof, custom_policy)
    print(f"\n  Excellent User evaluation: {'PASS' if passes else 'FAIL'}")
    if not passes:
        for reason in reasons:
            print(f"    - {reason}")

    # =========================================================
    # Summary
    # =========================================================
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    summary = verifier.get_verification_summary()
    print(f"\nVerification Statistics:")
    print(f"  Total verifications: {summary['total_verifications']}")
    print(f"  Verified: {summary['verified']}")
    print(f"  Failed: {summary['failed']}")
    print(f"  Success rate: {summary['success_rate']:.1%}")

    print("\n" + "=" * 60)
    print("ZK-Credit Demo Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
