"""
ZK-Solvency Exploration Script

Phase 4: 探索零知识储备金证明系统

本脚本演示:
1. Merkle Sum Tree - 负债承诺
2. 资产承诺和证明
3. 储备金证明生成
4. 用户独立验证
"""

import secrets
from datetime import datetime

print("=" * 60)
print("ZK-Solvency: 零知识储备金证明系统")
print("=" * 60)


# ============================================================
# Part 1: Merkle Sum Tree
# ============================================================
print("\n" + "=" * 60)
print("Part 1: Merkle Sum Tree (负债承诺)")
print("=" * 60)

from src.solvency.merkle_sum_tree import (
    MerkleSumTree,
    MerkleSumTreeBuilder,
    UserBalance,
    AssetType,
)

# 创建用户余额
print("\n--- 创建用户余额 ---")
balances = [
    UserBalance(
        user_id="alice@example.com",
        user_hash=b'',
        balance=int(10 * 10**18),  # 10 ETH
        asset_type=AssetType.ETH
    ),
    UserBalance(
        user_id="bob@example.com",
        user_hash=b'',
        balance=int(5.5 * 10**18),  # 5.5 ETH
        asset_type=AssetType.ETH
    ),
    UserBalance(
        user_id="charlie@example.com",
        user_hash=b'',
        balance=int(20 * 10**18),  # 20 ETH
        asset_type=AssetType.ETH
    ),
    UserBalance(
        user_id="diana@example.com",
        user_hash=b'',
        balance=int(3.2 * 10**18),  # 3.2 ETH
        asset_type=AssetType.ETH
    ),
]

print(f"用户数量: {len(balances)}")
total_balance = sum(b.balance for b in balances)
print(f"总余额: {total_balance / 10**18:.4f} ETH")

# 构建Merkle Sum Tree
print("\n--- 构建Merkle Sum Tree ---")
tree = MerkleSumTree()
root = tree.build_tree(balances)

print(f"根哈希: {root.hash.hex()[:32]}...")
print(f"总负债: {tree.get_total_liabilities() / 10**18:.4f} ETH")

stats = tree.get_statistics()
print(f"树高度: {stats['tree_height']}")
print(f"用户数量: {stats['total_users']}")

# 生成用户包含证明
print("\n--- 生成用户包含证明 ---")
alice_hash = balances[0].user_hash
alice_proof = tree.generate_inclusion_proof(alice_hash)

if alice_proof:
    print(f"证明ID: {alice_proof.proof_id}")
    print(f"用户余额: {alice_proof.balance / 10**18:.4f} ETH")
    print(f"证明路径长度: {len(alice_proof.proof_path)}")
    print(f"总负债: {alice_proof.total_liabilities / 10**18:.4f} ETH")

    # 验证包含证明
    is_valid, msg = tree.verify_inclusion_proof(alice_proof)
    print(f"验证结果: {is_valid} - {msg}")


# ============================================================
# Part 2: 资产承诺
# ============================================================
print("\n" + "=" * 60)
print("Part 2: 资产承诺 (Asset Commitment)")
print("=" * 60)

from src.solvency.asset_commitment import (
    Asset,
    AssetCommitment,
    AssetProver,
    AssetVerifier,
    ChainType,
    WalletType,
)

# 创建资产记录
print("\n--- 创建资产记录 ---")
assets = [
    Asset(
        asset_id="hot_wallet_1",
        asset_type=AssetType.ETH,
        chain=ChainType.ETHEREUM,
        address="0xHotWallet1234567890abcdef",
        balance=int(25 * 10**18),  # 25 ETH
        wallet_type=WalletType.HOT_WALLET,
        last_verified=datetime.now(),
        verification_block=18500000
    ),
    Asset(
        asset_id="cold_wallet_1",
        asset_type=AssetType.ETH,
        chain=ChainType.ETHEREUM,
        address="0xColdWallet0987654321fedcba",
        balance=int(50 * 10**18),  # 50 ETH
        wallet_type=WalletType.COLD_WALLET,
        last_verified=datetime.now(),
        verification_block=18500000
    ),
]

total_assets = sum(a.balance for a in assets)
print(f"资产数量: {len(assets)}")
print(f"总资产: {total_assets / 10**18:.4f} ETH")

for a in assets:
    print(f"  - {a.asset_id}: {a.balance / 10**18:.4f} ETH ({a.wallet_type.value})")

# 创建资产承诺
print("\n--- 创建资产承诺 ---")
asset_prover = AssetProver()
asset_verifier = AssetVerifier()

commitments = []
for asset in assets:
    commitment = asset_prover.create_commitment(asset)
    commitments.append(commitment)
    print(f"{asset.asset_id}: 承诺点 ({commitment.commitment.x.value % 10**10}...)")

# 生成余额证明
print("\n--- 生成资产证明 ---")
balance_proof = asset_prover.prove_balance(commitments[0])
print(f"证明类型: {balance_proof.proof_type}")
print(f"证明ID: {balance_proof.proof_id}")

is_valid, msg = asset_verifier.verify_balance_proof(balance_proof)
print(f"验证结果: {is_valid} - {msg}")

# 生成范围证明
print("\n--- 生成范围证明 ---")
range_proof = asset_prover.prove_range(commitments[1], lower_bound=int(40 * 10**18))
print(f"证明类型: {range_proof.proof_type}")
print(f"下界: {range_proof.range_lower_bound / 10**18:.4f} ETH")

is_valid, msg = asset_verifier.verify_range_proof(range_proof)
print(f"验证结果: {is_valid} - {msg}")


# ============================================================
# Part 3: 储备金证明
# ============================================================
print("\n" + "=" * 60)
print("Part 3: 储备金证明 (Proof of Reserves)")
print("=" * 60)

from src.solvency.proof_of_reserves import (
    ReservesProver,
    ReservesVerifier,
    SolvencyStatus,
    create_proof_of_reserves,
)

# 创建证明器
print("\n--- 创建储备金证明 ---")
prover = ReservesProver(
    exchange_id="example_exchange",
    exchange_name="Example Exchange"
)

# 设置负债
prover.set_liabilities(balances)

# 添加资产
for asset in assets:
    prover.add_asset(asset)

# 获取统计
stats = prover.get_statistics()
print(f"交易所: {stats['exchange_name']}")
print(f"用户数: {stats['total_users']}")
print(f"总负债: {stats['total_liabilities'] / 10**18:.4f} ETH")
print(f"总资产: {stats['total_assets'] / 10**18:.4f} ETH")
print(f"偿付比率: {stats['solvency_ratio']:.2%}")

# 生成储备金证明
reserves_proof = prover.generate_proof(validity_hours=24)

print(f"\n证明ID: {reserves_proof.proof_id}")
print(f"状态: {reserves_proof.status.value}")
print(f"负债根: {reserves_proof.liability_root.hex()[:32]}...")
print(f"资产承诺数: {len(reserves_proof.asset_commitments)}")

# 验证储备金证明
print("\n--- 验证储备金证明 ---")
verifier = ReservesVerifier()

is_valid, msg, status = verifier.verify_proof(reserves_proof)
print(f"验证结果: {is_valid}")
print(f"消息: {msg}")
print(f"状态: {status.value}")

# 生成审计报告
print("\n--- 生成审计报告 ---")
audit_report = verifier.generate_audit_report(
    reserves_proof,
    auditor="ZK-Audit Services",
    audit_type="full"
)

print(f"报告ID: {audit_report.report_id}")
print(f"审计方: {audit_report.auditor}")
print(f"是否有偿付能力: {audit_report.is_solvent}")
print(f"发现: {audit_report.findings}")
print(f"建议: {audit_report.recommendations}")


# ============================================================
# Part 4: 用户独立验证
# ============================================================
print("\n" + "=" * 60)
print("Part 4: 用户独立验证 (Individual Verification)")
print("=" * 60)

from src.solvency.individual_verification import (
    UserVerifier,
    UserProofExporter,
    VerificationStatus,
)

# 为Alice生成用户证明
print("\n--- 为用户生成证明 ---")
user_verifier = UserVerifier()

# 获取Alice的包含证明
alice_inclusion = prover.generate_user_proof(balances[0].user_hash)

if alice_inclusion:
    # 创建用户证明包
    alice_user_proof = user_verifier.create_user_proof(
        user_id="alice@example.com",
        balance=balances[0].balance,
        asset_type=AssetType.ETH,
        inclusion_proof=alice_inclusion,
        reserves_proof=reserves_proof
    )

    print(f"用户证明ID: {alice_user_proof.proof_id}")
    print(f"用户余额: {alice_user_proof.balance / 10**18:.4f} ETH")
    print(f"交易所: {alice_user_proof.exchange_name}")

    # 用户独立验证
    print("\n--- 用户独立验证 ---")
    verification_result = user_verifier.verify_user_proof(
        alice_user_proof,
        expected_balance=balances[0].balance,
        reserves_proof=reserves_proof
    )

    print(f"验证状态: {verification_result.status.value}")
    print(f"是否有效: {verification_result.is_valid}")
    print(f"余额验证: {verification_result.balance_verified}")
    print(f"包含验证: {verification_result.inclusion_verified}")
    print(f"根哈希匹配: {verification_result.root_hash_matched}")

    if verification_result.errors:
        print(f"错误: {verification_result.errors}")
    if verification_result.warnings:
        print(f"警告: {verification_result.warnings}")

    # 导出用户证明
    print("\n--- 导出用户证明 ---")
    json_proof = UserProofExporter.to_json(alice_user_proof)
    print(f"JSON长度: {len(json_proof)} 字符")

    qr_data = UserProofExporter.to_qr_data(alice_user_proof)
    print(f"QR数据长度: {len(qr_data)} 字节")

    # 从JSON恢复
    restored_proof = UserProofExporter.from_json(json_proof)
    print(f"恢复证明ID: {restored_proof.proof_id}")


# ============================================================
# Part 5: 边缘情况测试
# ============================================================
print("\n" + "=" * 60)
print("Part 5: 边缘情况测试")
print("=" * 60)

# 测试不足资产的情况
print("\n--- 测试资产不足情况 ---")

insufficient_prover = ReservesProver(
    exchange_id="risky_exchange",
    exchange_name="Risky Exchange"
)

# 设置更多负债
large_balances = [
    UserBalance(
        user_id=f"user_{i}@example.com",
        user_hash=b'',
        balance=int(100 * 10**18),  # 每人100 ETH
        asset_type=AssetType.ETH
    )
    for i in range(10)  # 1000 ETH总负债
]
insufficient_prover.set_liabilities(large_balances)

# 只添加少量资产
small_asset = Asset(
    asset_id="small_reserve",
    asset_type=AssetType.ETH,
    chain=ChainType.ETHEREUM,
    address="0xSmallReserve",
    balance=int(500 * 10**18),  # 只有500 ETH
    wallet_type=WalletType.HOT_WALLET
)
insufficient_prover.add_asset(small_asset)

risky_stats = insufficient_prover.get_statistics()
print(f"总负债: {risky_stats['total_liabilities'] / 10**18:.4f} ETH")
print(f"总资产: {risky_stats['total_assets'] / 10**18:.4f} ETH")
print(f"偿付比率: {risky_stats['solvency_ratio']:.2%}")

# 生成证明（会显示不足）
risky_proof = insufficient_prover.generate_proof()
print(f"状态: {risky_proof.status.value}")

# 验证
is_valid, msg, status = verifier.verify_proof(risky_proof)
print(f"验证结果: {is_valid} - {status.value}")


# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("ZK-Solvency 系统总结")
print("=" * 60)

print("""
核心功能:
1. Merkle Sum Tree: 承诺所有用户余额，支持包含证明
2. 资产承诺: Pedersen承诺隐藏资产余额
3. 储备金证明: 证明资产 >= 负债，不泄露具体数值
4. 用户验证: 用户可独立验证自己的余额被正确包含

技术特点:
- 零知识: 不泄露任何个人余额或总资产
- 可验证: 用户可独立验证，无需信任交易所
- 高效: Merkle路径证明，O(log n)复杂度
- 可审计: 支持第三方审计报告生成

应用场景:
- 交易所储备证明: 定期发布储备金证明
- 用户信任: 用户可自行验证资金安全
- 监管合规: 满足监管要求的透明度
- 危机预防: 早期发现资不抵债问题
""")

# 验证历史摘要
summary = user_verifier.get_verification_summary()
print(f"\n验证统计:")
print(f"  总验证次数: {summary['total_verifications']}")
print(f"  成功: {summary['verified']}")
print(f"  失败: {summary['failed']}")
print(f"  成功率: {summary['success_rate']:.0%}")

print("\nPhase 4 ZK-Solvency 模块完成!")
print("=" * 60)
