"""
ZK-AML Exploration Script

Phase 3: 探索零知识反洗钱系统

本脚本演示:
1. 制裁名单筛查 - 证明地址不在OFAC等制裁名单
2. 来源证明 - 证明资金来源合规
3. Privacy Pools - 关联集证明
4. 综合AML验证 - 多策略合规检查
"""

import secrets
from datetime import datetime

print("=" * 60)
print("ZK-AML: 零知识反洗钱系统")
print("=" * 60)


# ============================================================
# Part 1: 制裁名单筛查
# ============================================================
print("\n" + "=" * 60)
print("Part 1: 制裁名单筛查 (Sanctions Screening)")
print("=" * 60)

from src.aml.sanctions import (
    SanctionsScreener,
    SanctionsList,
    SanctionsListType,
    SanctionedEntity,
    OFAC_SDN_LIST,
    EU_SANCTIONS_LIST,
    UN_SANCTIONS_LIST,
    create_default_screener,
)

# 创建默认筛查器(已注册所有名单)
screener = create_default_screener()

print(f"\n已注册 {len(screener.sanctions_lists)} 个制裁名单")
for list_type, slist in screener.sanctions_lists.items():
    print(f"  - {list_type.value}: {slist.size} 个地址")

# 添加一些模拟的制裁地址到entity_sets
sanctioned_addr = "0xSANCTIONED1234567890abcdef"
import hashlib
sanctioned_addr_id = hashlib.sha256(sanctioned_addr.lower().encode()).hexdigest()
screener.entity_sets[SanctionsListType.OFAC_SDN].add(sanctioned_addr_id)

print(f"\n添加测试制裁地址: {sanctioned_addr[:20]}...")

# 测试普通地址(非制裁)
clean_address = "0xClean1234567890abcdef1234567890abcdef"

print("\n--- 测试非制裁地址 ---")

# 创建地址承诺
commitment = screener.create_address_commitment(clean_address)
print(f"地址承诺: ({commitment.commitment.x.value % 10**10}...)")

# 生成非制裁证明
proof = screener.prove_not_sanctioned(clean_address, commitment)
print(f"证明类型: {proof.proof_type}")
print(f"证明有效: {proof.is_valid()}")
print(f"已检查名单: {[lt.value for lt in proof.screened_lists]}")

# 验证证明
is_valid = screener.verify_not_sanctioned(proof)
print(f"验证结果: {is_valid}")

# 测试制裁地址
print("\n--- 测试制裁地址 ---")
sanctioned_commitment = screener.create_address_commitment(sanctioned_addr)

try:
    sanctioned_proof = screener.prove_not_sanctioned(sanctioned_addr, sanctioned_commitment)
    print(f"证明有效: {sanctioned_proof.is_valid()}")
except ValueError as e:
    print(f"证明失败(预期): {e}")


# ============================================================
# Part 2: 来源证明
# ============================================================
print("\n" + "=" * 60)
print("Part 2: 来源证明 (Source Proof)")
print("=" * 60)

from src.aml.source_proof import (
    SourceProver,
    SourceVerifier,
    SourceType,
    RiskLevel,
    TransactionSource,
    COMPLIANT_SOURCES,
)

source_prover = SourceProver()
source_verifier = SourceVerifier()

# 模拟交易来源记录
test_address = "0xUser1234567890abcdef"
from datetime import datetime as dt

# 创建模拟交易记录
mock_transactions = [
    TransactionSource(
        tx_hash="0xTx001",
        source_type=SourceType.CEX_WITHDRAWAL,
        from_address="0xBinanceHotWallet",
        to_address=test_address,
        amount=int(5 * 10**18),  # 5 ETH
        block_number=18000000,
        timestamp=dt.now(),
        platform="binance",
        risk_level=RiskLevel.LOW,
        verified=True,
        verifier="Binance"
    ),
    TransactionSource(
        tx_hash="0xTx002",
        source_type=SourceType.DEFI_SWAP,
        from_address="0xUniswapRouter",
        to_address=test_address,
        amount=int(2 * 10**18),  # 2 ETH
        block_number=18000100,
        timestamp=dt.now(),
        platform="uniswap",
        risk_level=RiskLevel.LOW,
        verified=False
    ),
]

print("\n--- 分析来源链 ---")
source_chain = source_prover.analyze_source_chain(
    test_address,
    mock_transactions,
    max_depth=3
)

print(f"当前地址: {source_chain.current_address[:20]}...")
print(f"交易数量: {len(source_chain.transactions)}")
print(f"链深度: {source_chain.depth}")
print(f"最高风险: {source_chain.max_risk_level.name}")
print(f"有验证来源: {source_chain.has_verified_origin}")

print("\n交易详情:")
for i, tx in enumerate(source_chain.transactions, 1):
    print(f"  {i}. {tx.source_type.value}")
    print(f"     金额: {tx.amount / 10**18:.4f} ETH")
    print(f"     风险: {tx.risk_level.name}")

# 生成合规证明
print("\n--- 生成来源合规证明 ---")
source_proof = source_prover.prove_compliant_source(test_address, source_chain)

print(f"证明类型: {source_proof.proof_type}")
print(f"披露风险等级: {source_proof.disclosed_risk_level.name if source_proof.disclosed_risk_level else 'N/A'}")
print(f"有效期至: {source_proof.valid_until}")
print(f"地址承诺: ({source_proof.address_commitment.x.value % 10**10}...)")

# 验证来源证明
is_valid = source_verifier.verify_compliant_source(source_proof)
print(f"验证结果: {is_valid}")


# ============================================================
# Part 3: Privacy Pools 关联集证明
# ============================================================
print("\n" + "=" * 60)
print("Part 3: Privacy Pools 关联集证明")
print("=" * 60)

from src.aml.privacy_pools import (
    PrivacyPool,
    PrivacyPoolProver,
    PrivacyPoolVerifier,
    AssociationSet,
    AssociationSetType,
    PoolStatus,
    COMPLIANT_EXCHANGE_SET,
    VERIFIED_DEFI_SET,
)

pool_prover = PrivacyPoolProver()
pool_verifier = PrivacyPoolVerifier()

# 创建隐私池
pool = PrivacyPool(
    pool_id="main_pool_v1",
    name="Main Privacy Pool",
    denomination=1 * 10**18  # 1 ETH
)

print(f"\n创建隐私池: {pool.name}")
print(f"面额: {pool.denomination / 10**18} ETH")

# 注册关联集
pool.register_association_set(COMPLIANT_EXCHANGE_SET)
pool.register_association_set(VERIFIED_DEFI_SET)

print(f"\n注册关联集:")
for set_id, assoc_set in pool.association_sets.items():
    print(f"  - {assoc_set.name} ({assoc_set.set_type.value})")

# 添加成员到关联集
member_addresses = [
    "0xBinanceUser001",
    "0xCoinbaseUser002",
    "0xKrakenUser003",
    "0xGeminiUser004",
]

print("\n--- 添加成员到合规交易所关联集 ---")
for addr in member_addresses:
    commitment = secrets.token_bytes(32)
    COMPLIANT_EXCHANGE_SET.add_member(addr, commitment)

print(f"当前成员数: {COMPLIANT_EXCHANGE_SET.member_count}")

# 更新Merkle根
from src.zkp.commitment import MerkleTreeCommitment
merkle = MerkleTreeCommitment()
member_bytes = [m.encode() for m in COMPLIANT_EXCHANGE_SET.members]
if member_bytes:
    root, _ = merkle.commit(member_bytes)
    COMPLIANT_EXCHANGE_SET.merkle_root = root
    print(f"Merkle根: {root.hex()[:32]}...")

# 创建存款
print("\n--- 创建存款 ---")
depositor_secret = secrets.token_bytes(32)
deposit = pool_prover.create_deposit(
    pool,
    depositor_secret,
    1 * 10**18,  # 1 ETH
    source_chain="ethereum",
    source_protocol="binance"
)

print(f"存款ID: {deposit.deposit_id}")
print(f"叶子索引: {deposit.leaf_index}")
print(f"Nullifier哈希: {deposit.nullifier_hash.hex()[:32]}...")

# 验证存款
is_valid = pool_verifier.verify_deposit(pool, deposit)
print(f"存款有效: {is_valid}")

# 生成关联证明
print("\n--- 生成关联证明 ---")
member_addr = "0xBinanceUser001"
member_secret = secrets.token_bytes(32)

assoc_proof = pool_prover.prove_association(
    pool,
    COMPLIANT_EXCHANGE_SET.set_id,
    member_addr,
    member_secret
)

if assoc_proof:
    print(f"证明ID: {assoc_proof.proof_id}")
    print(f"关联集: {assoc_proof.association_set_id}")
    print(f"证明有效: {assoc_proof.is_valid}")

    # 验证关联证明
    is_valid, msg = pool_verifier.verify_association_proof(
        assoc_proof,
        COMPLIANT_EXCHANGE_SET
    )
    print(f"验证结果: {is_valid} - {msg}")


# ============================================================
# Part 4: 综合AML验证
# ============================================================
print("\n" + "=" * 60)
print("Part 4: 综合AML验证 (Unified Verification)")
print("=" * 60)

from src.aml.verifier import (
    AMLVerifier,
    AMLPolicy,
    BASIC_AML_POLICY,
    STRICT_AML_POLICY,
    DEFI_AML_POLICY,
)

# 使用基础策略
print("\n--- 使用基础AML策略 ---")
verifier = AMLVerifier(BASIC_AML_POLICY)

print(f"策略: {verifier.policy.name}")
print(f"要求数量: {len(verifier.policy.requirements)}")
print(f"制裁名单: {[lt.value for lt in verifier.policy.sanctions_lists]}")
print(f"最大风险: {verifier.policy.max_risk_level.name}")

# 验证普通地址
test_addr = "0xTestUser12345"
test_secret = secrets.token_bytes(32)

result = verifier.verify_address(
    test_addr,
    test_secret,
    source_tx_hash="0xSourceTx123",
    source_chain="ethereum"
)

print(f"\n验证结果:")
print(f"  合规: {result.is_compliant}")
print(f"  风险等级: {result.overall_risk_level.name}")
print(f"  制裁检查: {'通过' if result.sanctions_check_passed else '失败'}")
print(f"  来源验证: {'通过' if result.source_verified else '未验证'}")

# 生成合规报告
print("\n--- 合规报告 ---")
report = verifier.get_compliance_report(result)
print(f"验证ID: {report['verification_id']}")
print(f"策略: {report['policy']['name']} v{report['policy']['version']}")
print(f"时间: {report['timestamp']}")
print(f"总体结果: {'合规' if report['overall_result']['is_compliant'] else '不合规'}")

if result.warnings:
    print(f"\n警告:")
    for w in result.warnings:
        print(f"  - {w}")

# 测试严格策略
print("\n--- 使用严格AML策略 ---")
strict_verifier = AMLVerifier(STRICT_AML_POLICY)

print(f"策略: {strict_verifier.policy.name}")
print(f"强制要求:")
for req in strict_verifier.policy.get_mandatory_requirements():
    print(f"  - {req.name}: {req.description}")

# 使用严格策略验证(需要更多证明)
strict_result = strict_verifier.verify_address(
    test_addr,
    test_secret,
    source_tx_hash="0xSourceTx123"
)

print(f"\n严格验证结果:")
print(f"  合规: {strict_result.is_compliant}")
print(f"  风险等级: {strict_result.overall_risk_level.name}")

if strict_result.errors:
    print(f"\n错误:")
    for e in strict_result.errors:
        print(f"  - {e}")

# 测试DeFi策略
print("\n--- 使用DeFi AML策略 ---")
defi_verifier = AMLVerifier(DEFI_AML_POLICY)

print(f"策略: {defi_verifier.policy.name}")
print(f"允许来源类型: {[st.value for st in defi_verifier.policy.allowed_source_types]}")

defi_result = defi_verifier.verify_address(
    test_addr,
    test_secret,
    source_tx_hash="0xDeFiSwap123"
)

print(f"\nDeFi验证结果:")
print(f"  合规: {defi_result.is_compliant}")
print(f"  风险等级: {defi_result.overall_risk_level.name}")


# ============================================================
# Part 5: 批量验证演示
# ============================================================
print("\n" + "=" * 60)
print("Part 5: 批量验证")
print("=" * 60)

addresses_to_verify = [
    ("0xUser1_abc123", secrets.token_bytes(32)),
    ("0xUser2_def456", secrets.token_bytes(32)),
    ("0xUser3_ghi789", secrets.token_bytes(32)),
]

print(f"\n批量验证 {len(addresses_to_verify)} 个地址...")

results = verifier.batch_verify(addresses_to_verify)

print("\n批量验证结果:")
for i, (addr, _) in enumerate(addresses_to_verify):
    r = results[i]
    status = "✓ 合规" if r.is_compliant else "✗ 不合规"
    print(f"  {addr[:15]}... : {status} (风险: {r.overall_risk_level.name})")


# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("ZK-AML 系统总结")
print("=" * 60)

print("""
核心功能:
1. 制裁筛查: 零知识证明地址不在OFAC/EU/UN制裁名单
2. 来源证明: 验证资金来源合规，评估风险等级
3. Privacy Pools: 关联集证明，平衡隐私与合规
4. 策略引擎: 支持多种AML策略(基础/严格/DeFi)

技术特点:
- Pedersen承诺隐藏地址
- Merkle树实现集合成员证明
- 非成员证明(排序Merkle树)
- 可配置的合规策略
- 批量验证支持

应用场景:
- 交易所合规: 用户提款前验证
- DeFi协议: 流动性提供者筛查
- 跨链桥: 转账合规检查
- 隐私币/混币器: 合规出口
""")

print("\nPhase 3 ZK-AML 模块完成!")
print("=" * 60)
