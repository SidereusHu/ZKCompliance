"""
Phase 1 探索脚本：零知识证明基础库

演示：
1. 有限域与椭圆曲线运算
2. Pedersen承诺
3. 电路构建与R1CS
4. Schnorr证明协议
5. 简单的ZK证明流程
"""

import sys
sys.path.insert(0, "/Users/sidereus/Documents/FindJobs/ZKCompliance")

from src.zkp.primitives import (
    FiniteField,
    FieldElement,
    EllipticCurve,
    Point,
    BN128,
    BLS12_381,
    generate_keypair,
    schnorr_sign,
    schnorr_verify,
)
from src.zkp.commitment import (
    PedersenCommitment,
    HashCommitment,
    VectorCommitment,
    MerkleTreeCommitment,
)
from src.zkp.circuit import (
    Circuit,
    CircuitBuilder,
    GateType,
)
from src.zkp.prover import (
    Witness,
    Groth16Prover,
    SchnorrProver,
    SigmaProtocolProver,
)
from src.zkp.verifier import (
    Groth16Verifier,
    SchnorrVerifier,
    SigmaProtocolVerifier,
)


def demo_finite_field():
    """演示有限域运算"""
    print("\n" + "="*60)
    print("1. 有限域运算演示")
    print("="*60)

    # 使用BN128的标量域
    field = BN128.scalar_field
    print(f"\n使用域: F_p where p = {str(field.p)[:20]}...")

    # 基本运算
    a = field.element(12345)
    b = field.element(67890)

    print(f"\na = {a.value}")
    print(f"b = {b.value}")
    print(f"a + b = {(a + b).value}")
    print(f"a * b = {(a * b).value}")
    print(f"a - b = {(a - b).value}")
    print(f"a / b = {(a / b).value}")
    print(f"a^100 = {(a ** 100).value}")

    # 验证除法
    quotient = a / b
    print(f"\n验证: (a/b) * b = {(quotient * b).value} (应等于 {a.value})")

    # 逆元
    a_inv = a.inverse()
    print(f"a^(-1) = {a_inv.value}")
    print(f"a * a^(-1) = {(a * a_inv).value} (应为 1)")


def demo_elliptic_curve():
    """演示椭圆曲线运算"""
    print("\n" + "="*60)
    print("2. 椭圆曲线运算演示")
    print("="*60)

    curve = BN128
    print(f"\n使用曲线: {curve.name}")
    print(f"曲线方程: y² = x³ + {curve.a.value}x + {curve.b.value}")

    # 生成元
    G = curve.generator
    print(f"\n生成元 G:")
    print(f"  x = {str(G.x.value)[:30]}...")
    print(f"  y = {str(G.y.value)[:30]}...")
    print(f"  在曲线上: {G.on_curve()}")

    # 标量乘法
    k = 12345
    P = k * G
    print(f"\nk = {k}")
    print(f"P = k * G:")
    print(f"  x = {str(P.x.value)[:30]}...")
    print(f"  y = {str(P.y.value)[:30]}...")
    print(f"  在曲线上: {P.on_curve()}")

    # 点加法
    Q = 67890 * G
    R = P + Q
    print(f"\nQ = 67890 * G")
    print(f"R = P + Q:")
    print(f"  x = {str(R.x.value)[:30]}...")
    print(f"  在曲线上: {R.on_curve()}")

    # 验证: (a+b)*G = a*G + b*G
    direct = (k + 67890) * G
    print(f"\n验证分配律: (k+67890)*G == k*G + 67890*G: {direct == R}")


def demo_pedersen_commitment():
    """演示Pedersen承诺"""
    print("\n" + "="*60)
    print("3. Pedersen承诺演示")
    print("="*60)

    pedersen = PedersenCommitment()
    print(f"\n使用曲线: {pedersen.curve.name}")

    # 基本承诺
    value = 100
    commitment, randomness = pedersen.commit(value)
    print(f"\n承诺值: {value}")
    print(f"随机数: {randomness}")
    print(f"承诺点 C:")
    print(f"  x = {str(commitment.x.value)[:30]}...")

    # 验证
    valid = pedersen.verify(commitment, value, randomness)
    print(f"\n验证承诺: {valid}")

    # 错误值验证
    wrong_valid = pedersen.verify(commitment, value + 1, randomness)
    print(f"验证错误值: {wrong_valid} (应为 False)")

    # 加法同态性
    print("\n[加法同态性演示]")
    v1, v2 = 30, 70
    c1, r1 = pedersen.commit(v1)
    c2, r2 = pedersen.commit(v2)

    # C(v1) + C(v2) = C(v1 + v2)
    c_sum = pedersen.add_commitments(c1, c2)
    r_sum = (r1 + r2) % pedersen.curve.n

    valid_sum = pedersen.verify(c_sum, v1 + v2, r_sum)
    print(f"  C({v1}) + C({v2}) = C({v1 + v2})")
    print(f"  验证和承诺: {valid_sum}")


def demo_hash_commitment():
    """演示哈希承诺"""
    print("\n" + "="*60)
    print("4. 哈希承诺演示")
    print("="*60)

    hash_commit = HashCommitment()

    # 字符串承诺
    secret = b"My secret message"
    commitment, randomness = hash_commit.commit(secret)

    print(f"\n秘密: {secret.decode()}")
    print(f"承诺: {commitment.hex()[:32]}...")
    print(f"随机数: {randomness.hex()[:32]}...")

    # 验证
    valid = hash_commit.verify(commitment, secret, randomness)
    print(f"\n验证: {valid}")

    # 整数承诺
    value = 42
    c_int, r_int = hash_commit.commit_integer(value)
    print(f"\n整数承诺: {value}")
    print(f"承诺: {c_int.hex()[:32]}...")
    valid_int = hash_commit.verify_integer(c_int, value, r_int)
    print(f"验证: {valid_int}")


def demo_merkle_tree():
    """演示Merkle树承诺"""
    print("\n" + "="*60)
    print("5. Merkle树承诺演示")
    print("="*60)

    merkle = MerkleTreeCommitment()

    # 构建树
    values = [b"Alice", b"Bob", b"Charlie", b"David"]
    root, randomnesses = merkle.commit(values)

    print(f"\n值列表: {[v.decode() for v in values]}")
    print(f"Merkle根: {root.hex()[:32]}...")

    # 生成成员证明
    index = 1  # Bob
    proof = merkle.get_proof(index)
    print(f"\n为 '{values[index].decode()}' (索引 {index}) 生成证明")
    print(f"证明路径长度: {len(proof)}")

    # 验证
    valid = merkle.verify(root, values[index], randomnesses[index], index, proof)
    print(f"验证成员证明: {valid}")


def demo_circuit():
    """演示电路构建"""
    print("\n" + "="*60)
    print("6. 电路构建演示")
    print("="*60)

    # 构建简单电路: 证明知道 x 使得 x² + x + 5 = y
    circuit = Circuit(name="quadratic")

    # 输入
    x = circuit.private_input("x")  # 私密输入
    y = circuit.public_input("y")   # 公开输出

    # 计算 x² + x + 5
    x_squared = circuit.mul(x, x)        # x²
    x_plus_x2 = circuit.add(x, x_squared) # x + x²
    five = circuit.constant(5)            # 5
    result = circuit.add(x_plus_x2, five) # x² + x + 5

    # 约束: result == y
    circuit.assert_equal(result, y)

    # 电路统计
    stats = circuit.stats()
    print(f"\n电路: {circuit.name}")
    print(f"  线路数: {stats['wires']}")
    print(f"  公开输入: {stats['public_inputs']}")
    print(f"  私密输入: {stats['private_inputs']}")
    print(f"  约束数: {stats['constraints']}")

    # 导出R1CS
    constraints, num_vars, num_public, num_private = circuit.to_r1cs()
    print(f"\nR1CS约束系统:")
    print(f"  变量数: {num_vars}")
    print(f"  公开变量: {num_public}")
    print(f"  私密变量: {num_private}")
    print(f"  约束数: {len(constraints)}")

    # 验证见证
    # x = 3, y = 3² + 3 + 5 = 17
    x_val = 3
    y_val = x_val * x_val + x_val + 5

    assignment = {
        circuit.one.wire_id: 1,
        x.wire_id: x_val,
        y.wire_id: y_val,
        x_squared.wire_id: x_val * x_val,
        x_plus_x2.wire_id: x_val + x_val * x_val,
        five.wire_id: 5,
        result.wire_id: y_val,
    }

    valid = circuit.verify_witness(assignment)
    print(f"\n见证验证 (x={x_val}, y={y_val}): {valid}")


def demo_schnorr_protocol():
    """演示Schnorr证明协议"""
    print("\n" + "="*60)
    print("7. Schnorr协议演示")
    print("="*60)

    curve = BN128

    # 生成密钥对
    sk, pk = generate_keypair(curve)
    print(f"\n生成密钥对:")
    print(f"  私钥 sk = {str(sk)[:30]}...")
    print(f"  公钥 pk = Point(...)")

    # 签名
    message = b"Hello, Zero Knowledge!"
    R, s = schnorr_sign(message, sk, curve)
    print(f"\n消息: {message.decode()}")
    print(f"签名:")
    print(f"  R = Point(...)")
    print(f"  s = {str(s)[:30]}...")

    # 验证
    valid = schnorr_verify(message, (R, s), pk, curve)
    print(f"\n验证签名: {valid}")

    # 验证错误消息
    wrong_msg = b"Wrong message"
    wrong_valid = schnorr_verify(wrong_msg, (R, s), pk, curve)
    print(f"验证错误消息: {wrong_valid} (应为 False)")


def demo_sigma_protocol():
    """演示Sigma协议"""
    print("\n" + "="*60)
    print("8. Sigma协议演示")
    print("="*60)

    curve = BN128
    prover = SigmaProtocolProver(curve)
    verifier = SigmaProtocolVerifier(curve)

    # 离散对数相等证明
    print("\n[离散对数相等证明]")
    print("证明: log_G1(H1) = log_G2(H2)")

    x = curve.random_scalar()
    G1 = curve.generator
    G2 = curve.hash_to_curve(b"G2")
    H1 = x * G1
    H2 = x * G2

    R1, R2, s = prover.prove_dlog_equality(x, G1, H1, G2, H2)
    valid = verifier.verify_dlog_equality(R1, R2, s, G1, H1, G2, H2)
    print(f"  验证结果: {valid}")

    # OR证明
    print("\n[离散对数OR证明]")
    print("证明: 知道 log_G1(H1) 或 log_G2(H2) (不泄露是哪个)")

    # 只知道第一个
    x1 = curve.random_scalar()
    x2_fake = curve.random_scalar()  # 不知道真正的x2
    H1_real = x1 * G1
    H2_random = curve.random_point()  # 随机点，不知道其离散对数

    R1, R2, e1, e2, s1, s2 = prover.prove_dlog_or(x1, 0, G1, H1_real, G2, H2_random)
    valid_or = verifier.verify_dlog_or(R1, R2, e1, e2, s1, s2, G1, H1_real, G2, H2_random)
    print(f"  验证结果: {valid_or}")


def demo_simple_zk_proof():
    """演示简单的ZK证明流程"""
    print("\n" + "="*60)
    print("9. 简单ZK证明流程演示")
    print("="*60)

    print("\n场景: 证明知道两个数的乘积，而不泄露这两个数")
    print("公开: 乘积 c = 21")
    print("私密: a = 3, b = 7")

    curve = BN128

    # 构建电路: a * b = c
    circuit = Circuit(name="multiplication")
    a = circuit.private_input("a")
    b = circuit.private_input("b")
    c = circuit.public_input("c")

    product = circuit.mul(a, b)
    circuit.assert_equal(product, c)

    print(f"\n电路约束数: {circuit.stats()['constraints']}")

    # 设置
    prover = Groth16Prover(curve)
    proving_key = prover.setup(circuit)
    print(f"证明密钥生成完成")

    verifier = Groth16Verifier(curve)
    verification_key = verifier.derive_verification_key(proving_key)
    print(f"验证密钥生成完成")

    # 计算见证
    witness = prover.compute_witness(circuit, {"a": 3, "b": 7, "c": 21})
    print(f"\n见证计算完成")

    # 验证见证满足约束
    assignment = witness.get_assignment()
    assignment[circuit.one.wire_id] = 1
    assignment[product.wire_id] = 21
    valid_witness = circuit.verify_witness(assignment)
    print(f"见证验证: {valid_witness}")

    # 生成证明
    proof = prover.prove(circuit, witness, proving_key)
    print(f"\n生成证明:")
    print(f"  π_A = Point(...)")
    print(f"  π_B = Point(...)")
    print(f"  π_C = Point(...)")
    print(f"  类型: {proof.proof_type}")

    # 验证证明
    public_inputs = [21]  # 公开输入
    valid = verifier.verify(proof, public_inputs, verification_key)
    print(f"\n验证证明: {valid}")


def demo_compliance_preview():
    """预览合规应用场景"""
    print("\n" + "="*60)
    print("10. 合规应用场景预览")
    print("="*60)

    print("""
┌─────────────────────────────────────────────────────────────┐
│                   ZK-Compliance 应用场景                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Phase 2: ZK-KYC (年龄验证)                                 │
│  ─────────────────────────                                  │
│  • 证明: 年龄 >= 18                                         │
│  • 不泄露: 具体出生日期                                     │
│  • 技术: 范围证明 + 承诺                                    │
│                                                             │
│  Phase 3: ZK-AML (资金来源)                                 │
│  ─────────────────────────                                  │
│  • 证明: 资金不来自制裁地址                                 │
│  • 不泄露: 完整交易历史                                     │
│  • 技术: 集合非成员证明                                     │
│                                                             │
│  Phase 4: ZK-Solvency (储备证明)                            │
│  ─────────────────────────                                  │
│  • 证明: 总资产 >= 总负债                                   │
│  • 不泄露: 单个用户余额                                     │
│  • 技术: 求和证明 + 范围证明                                │
│                                                             │
│  Phase 5: ZK-Credit (信用评分)                              │
│  ─────────────────────────                                  │
│  • 证明: 信用分 >= 阈值                                     │
│  • 不泄露: 具体分数和计算方式                               │
│  • 技术: 私密计算 + 范围证明                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
    """)


def main():
    """主函数"""
    print("\n" + "="*60)
    print("   ZK-Compliance - Phase 1: 零知识证明基础库")
    print("="*60)

    try:
        # 1. 有限域
        demo_finite_field()

        # 2. 椭圆曲线
        demo_elliptic_curve()

        # 3. Pedersen承诺
        demo_pedersen_commitment()

        # 4. 哈希承诺
        demo_hash_commitment()

        # 5. Merkle树
        demo_merkle_tree()

        # 6. 电路构建
        demo_circuit()

        # 7. Schnorr协议
        demo_schnorr_protocol()

        # 8. Sigma协议
        demo_sigma_protocol()

        # 9. 简单ZK证明
        demo_simple_zk_proof()

        # 10. 合规预览
        demo_compliance_preview()

        print("\n" + "="*60)
        print("Phase 1 探索完成!")
        print("="*60)
        print("\n主要功能模块:")
        print("  1. primitives.py   - 有限域与椭圆曲线")
        print("  2. commitment.py   - 承诺方案")
        print("  3. circuit.py      - 电路与R1CS")
        print("  4. prover.py       - 证明生成")
        print("  5. verifier.py     - 证明验证")

    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
