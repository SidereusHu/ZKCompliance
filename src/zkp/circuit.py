"""
电路抽象层

实现零知识证明的电路表示:
- R1CS (Rank-1 Constraint System) 约束系统
- 电路门和线路抽象
- 电路构建器
"""

from dataclasses import dataclass, field as dc_field
from typing import Dict, List, Optional, Tuple, Union, Callable, Any
from enum import Enum
import hashlib

from src.zkp.primitives import FiniteField, FieldElement, BN128


class GateType(Enum):
    """门类型"""
    ADD = "add"           # 加法门: c = a + b
    MUL = "mul"           # 乘法门: c = a * b
    CONST = "const"       # 常量门: c = k
    INPUT = "input"       # 输入门
    OUTPUT = "output"     # 输出门
    ASSERT_EQ = "eq"      # 断言相等
    ASSERT_BOOL = "bool"  # 断言布尔值


@dataclass
class Wire:
    """电路线路

    表示电路中的一个值/信号。
    """
    wire_id: int
    name: str = ""
    is_public: bool = False
    is_input: bool = False
    is_output: bool = False
    value: Optional[int] = None  # 实际值（证明时填充）

    def __repr__(self) -> str:
        prefix = ""
        if self.is_public:
            prefix = "pub_"
        elif self.is_input:
            prefix = "in_"
        elif self.is_output:
            prefix = "out_"
        return f"Wire({prefix}{self.name or self.wire_id})"

    def __hash__(self) -> int:
        return hash(self.wire_id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Wire):
            return self.wire_id == other.wire_id
        return False


@dataclass
class Gate:
    """电路门"""
    gate_type: GateType
    inputs: List[Wire]
    output: Wire
    constant: Optional[int] = None  # 用于常量门

    def __repr__(self) -> str:
        if self.gate_type == GateType.CONST:
            return f"Gate({self.output} = {self.constant})"
        elif self.gate_type == GateType.ADD:
            return f"Gate({self.output} = {self.inputs[0]} + {self.inputs[1]})"
        elif self.gate_type == GateType.MUL:
            return f"Gate({self.output} = {self.inputs[0]} * {self.inputs[1]})"
        return f"Gate({self.gate_type.value}, {self.inputs} -> {self.output})"


@dataclass
class R1CSConstraint:
    """R1CS约束

    形式: <A, x> * <B, x> = <C, x>

    其中:
    - A, B, C 是系数向量
    - x 是变量向量 (包含 1, 公开输入, 私密输入)
    """
    # 系数字典: {wire_id: coefficient}
    a: Dict[int, int]
    b: Dict[int, int]
    c: Dict[int, int]

    def evaluate(
        self,
        assignment: Dict[int, int],
        field: FiniteField
    ) -> bool:
        """评估约束是否满足"""
        def inner_product(coeffs: Dict[int, int]) -> int:
            result = 0
            for wire_id, coeff in coeffs.items():
                value = assignment.get(wire_id, 0)
                result = (result + coeff * value) % field.p
            return result

        a_val = inner_product(self.a)
        b_val = inner_product(self.b)
        c_val = inner_product(self.c)

        return (a_val * b_val) % field.p == c_val

    def __repr__(self) -> str:
        def format_linear(coeffs: Dict[int, int]) -> str:
            terms = []
            for wire_id, coeff in sorted(coeffs.items()):
                if coeff == 1:
                    terms.append(f"w{wire_id}")
                else:
                    terms.append(f"{coeff}*w{wire_id}")
            return " + ".join(terms) if terms else "0"

        return f"({format_linear(self.a)}) * ({format_linear(self.b)}) = ({format_linear(self.c)})"


class Circuit:
    """算术电路

    表示一个完整的计算电路，可转换为R1CS约束系统。
    """

    def __init__(self, name: str = "circuit", field: Optional[FiniteField] = None):
        self.name = name
        self.field = field or BN128.scalar_field

        # 线路管理
        self._wires: Dict[int, Wire] = {}
        self._wire_counter = 0

        # 特殊线路
        self._one_wire: Optional[Wire] = None  # 常量 1
        self._public_inputs: List[Wire] = []
        self._private_inputs: List[Wire] = []
        self._outputs: List[Wire] = []

        # 门和约束
        self._gates: List[Gate] = []
        self._constraints: List[R1CSConstraint] = []

        # 初始化常量1线路
        self._init_one_wire()

    def _init_one_wire(self):
        """初始化常量1线路"""
        self._one_wire = self._new_wire("one")
        self._one_wire.value = 1

    def _new_wire(self, name: str = "") -> Wire:
        """创建新线路"""
        wire = Wire(wire_id=self._wire_counter, name=name)
        self._wires[self._wire_counter] = wire
        self._wire_counter += 1
        return wire

    @property
    def one(self) -> Wire:
        """常量1线路"""
        return self._one_wire

    def public_input(self, name: str = "") -> Wire:
        """声明公开输入"""
        wire = self._new_wire(name or f"pub_{len(self._public_inputs)}")
        wire.is_public = True
        wire.is_input = True
        self._public_inputs.append(wire)
        return wire

    def private_input(self, name: str = "") -> Wire:
        """声明私密输入（见证）"""
        wire = self._new_wire(name or f"priv_{len(self._private_inputs)}")
        wire.is_input = True
        self._private_inputs.append(wire)
        return wire

    def output(self, wire: Wire, name: str = "") -> Wire:
        """声明输出"""
        wire.is_output = True
        wire.name = name or wire.name or f"out_{len(self._outputs)}"
        self._outputs.append(wire)
        return wire

    def constant(self, value: int) -> Wire:
        """常量值"""
        wire = self._new_wire(f"const_{value}")
        wire.value = value % self.field.p

        # 约束: wire = value * 1
        self._constraints.append(R1CSConstraint(
            a={self._one_wire.wire_id: value},
            b={self._one_wire.wire_id: 1},
            c={wire.wire_id: 1}
        ))

        gate = Gate(GateType.CONST, [], wire, constant=value)
        self._gates.append(gate)

        return wire

    def add(self, a: Wire, b: Wire) -> Wire:
        """加法门: c = a + b"""
        c = self._new_wire()

        # R1CS: (a + b) * 1 = c
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: 1, b.wire_id: 1},
            b={self._one_wire.wire_id: 1},
            c={c.wire_id: 1}
        ))

        gate = Gate(GateType.ADD, [a, b], c)
        self._gates.append(gate)

        return c

    def sub(self, a: Wire, b: Wire) -> Wire:
        """减法门: c = a - b"""
        c = self._new_wire()

        # R1CS: (a - b) * 1 = c
        # 等价于: a * 1 = c + b
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: 1},
            b={self._one_wire.wire_id: 1},
            c={c.wire_id: 1, b.wire_id: 1}
        ))

        gate = Gate(GateType.ADD, [a, b], c)  # 复用ADD类型
        self._gates.append(gate)

        return c

    def mul(self, a: Wire, b: Wire) -> Wire:
        """乘法门: c = a * b"""
        c = self._new_wire()

        # R1CS: a * b = c
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: 1},
            b={b.wire_id: 1},
            c={c.wire_id: 1}
        ))

        gate = Gate(GateType.MUL, [a, b], c)
        self._gates.append(gate)

        return c

    def mul_const(self, a: Wire, k: int) -> Wire:
        """常量乘法: c = k * a"""
        c = self._new_wire()

        # R1CS: k * a * 1 = c
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: k},
            b={self._one_wire.wire_id: 1},
            c={c.wire_id: 1}
        ))

        return c

    def assert_equal(self, a: Wire, b: Wire):
        """断言相等: a == b"""
        # R1CS: (a - b) * 1 = 0
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: 1, b.wire_id: self.field.p - 1},  # -1 mod p
            b={self._one_wire.wire_id: 1},
            c={}  # 0
        ))

        gate = Gate(GateType.ASSERT_EQ, [a, b], a)
        self._gates.append(gate)

    def assert_bool(self, a: Wire):
        """断言布尔值: a * (1 - a) = 0"""
        # a ∈ {0, 1} 等价于 a * (1-a) = 0
        # R1CS: a * (1 - a) = 0
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: 1},
            b={self._one_wire.wire_id: 1, a.wire_id: self.field.p - 1},
            c={}
        ))

        gate = Gate(GateType.ASSERT_BOOL, [a], a)
        self._gates.append(gate)

    def assert_zero(self, a: Wire):
        """断言为零: a == 0"""
        self._constraints.append(R1CSConstraint(
            a={a.wire_id: 1},
            b={self._one_wire.wire_id: 1},
            c={}
        ))

    def select(self, condition: Wire, if_true: Wire, if_false: Wire) -> Wire:
        """条件选择: result = condition ? if_true : if_false

        实现: result = condition * if_true + (1 - condition) * if_false
                     = condition * (if_true - if_false) + if_false
        """
        # 确保 condition 是布尔值
        self.assert_bool(condition)

        # diff = if_true - if_false
        diff = self.sub(if_true, if_false)

        # selected = condition * diff
        selected = self.mul(condition, diff)

        # result = selected + if_false
        result = self.add(selected, if_false)

        return result

    def is_zero(self, a: Wire) -> Wire:
        """检查是否为零，返回布尔值"""
        # 技巧：使用逆元
        # 如果 a != 0, 则存在 inv 使得 a * inv = 1
        # 如果 a == 0, 则 inv 可以是任意值

        inv = self.private_input("inv")  # 见证
        is_z = self.private_input("is_zero")  # 结果布尔值

        # 约束 1: a * inv = 1 - is_zero
        # 约束 2: a * is_zero = 0
        # 约束 3: is_zero 是布尔值

        prod = self.mul(a, inv)
        one_minus_is_z = self.sub(self.constant(1), is_z)
        self.assert_equal(prod, one_minus_is_z)

        check = self.mul(a, is_z)
        self.assert_zero(check)

        self.assert_bool(is_z)

        return is_z

    def to_r1cs(self) -> Tuple[List[R1CSConstraint], int, int, int]:
        """导出R1CS约束系统

        Returns:
            (constraints, num_vars, num_public, num_private)
        """
        num_vars = self._wire_counter
        num_public = len(self._public_inputs) + 1  # +1 for constant 1
        num_private = num_vars - num_public

        return self._constraints, num_vars, num_public, num_private

    def verify_witness(self, assignment: Dict[int, int]) -> bool:
        """验证见证是否满足所有约束"""
        # 确保常量1正确
        assignment[self._one_wire.wire_id] = 1

        for i, constraint in enumerate(self._constraints):
            if not constraint.evaluate(assignment, self.field):
                print(f"Constraint {i} failed: {constraint}")
                return False
        return True

    def stats(self) -> Dict[str, int]:
        """电路统计信息"""
        return {
            "wires": len(self._wires),
            "public_inputs": len(self._public_inputs),
            "private_inputs": len(self._private_inputs),
            "outputs": len(self._outputs),
            "gates": len(self._gates),
            "constraints": len(self._constraints),
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (f"Circuit({self.name}, "
                f"wires={s['wires']}, "
                f"constraints={s['constraints']})")


class CircuitBuilder:
    """电路构建辅助类

    提供更高级的电路构建原语。
    """

    def __init__(self, circuit: Optional[Circuit] = None):
        self.circuit = circuit or Circuit()

    def range_check(self, value: Wire, n_bits: int) -> List[Wire]:
        """范围检查: 证明 value ∈ [0, 2^n_bits)

        通过位分解实现:
        value = b0 + 2*b1 + 4*b2 + ... + 2^(n-1)*b(n-1)
        每个 bi ∈ {0, 1}

        Returns:
            位线路列表 [b0, b1, ..., b(n-1)]
        """
        bits = []
        accumulated = self.circuit.constant(0)

        for i in range(n_bits):
            bit = self.circuit.private_input(f"bit_{i}")
            self.circuit.assert_bool(bit)  # 确保是0或1
            bits.append(bit)

            # accumulated += 2^i * bit
            weighted = self.circuit.mul_const(bit, 1 << i)
            accumulated = self.circuit.add(accumulated, weighted)

        # 确保位分解正确
        self.circuit.assert_equal(accumulated, value)

        return bits

    def less_than(self, a: Wire, b: Wire, n_bits: int) -> Wire:
        """比较: a < b (都是n_bits位的数)

        技巧: a < b 等价于 a + 2^n - b 的第n位为1
        """
        # 计算 diff = a + 2^n - b
        power = self.circuit.constant(1 << n_bits)
        sum_val = self.circuit.add(a, power)
        diff = self.circuit.sub(sum_val, b)

        # 范围检查 diff
        bits = self.range_check(diff, n_bits + 1)

        # 返回最高位（第n位）
        return bits[n_bits]

    def hash_mimc(self, inputs: List[Wire], rounds: int = 220) -> Wire:
        """MiMC哈希 (ZK友好的哈希函数)

        MiMC: x_{i+1} = (x_i + k + c_i)^3

        简化版本用于演示。
        """
        # 常量轮密钥 (实际应用中应使用标准常量)
        round_constants = [
            int.from_bytes(hashlib.sha256(f"MiMC_round_{i}".encode()).digest(), 'big')
            % self.circuit.field.p
            for i in range(rounds)
        ]

        # 初始化状态
        state = inputs[0] if inputs else self.circuit.constant(0)

        for inp in inputs[1:]:
            state = self.circuit.add(state, inp)

        # MiMC轮
        for i in range(rounds):
            # x = x + c_i
            c = self.circuit.constant(round_constants[i])
            state = self.circuit.add(state, c)

            # x = x^3
            x2 = self.circuit.mul(state, state)
            state = self.circuit.mul(x2, state)

        return state

    def poseidon_hash(self, inputs: List[Wire]) -> Wire:
        """Poseidon哈希 (简化版)

        Poseidon是更高效的ZK友好哈希函数。
        这里提供简化的概念实现。
        """
        # 简化实现：线性组合 + 立方
        state = self.circuit.constant(0)

        for i, inp in enumerate(inputs):
            weighted = self.circuit.mul_const(inp, i + 1)
            state = self.circuit.add(state, weighted)

        # 非线性层: x^3
        x2 = self.circuit.mul(state, state)
        result = self.circuit.mul(x2, state)

        return result

    def merkle_proof(
        self,
        leaf: Wire,
        path: List[Wire],
        path_indices: List[Wire]  # 0=左, 1=右
    ) -> Wire:
        """验证Merkle证明

        Args:
            leaf: 叶子节点哈希
            path: 路径上的兄弟节点哈希
            path_indices: 每层的位置 (0=左子节点, 1=右子节点)

        Returns:
            计算得到的根哈希
        """
        current = leaf

        for sibling, index in zip(path, path_indices):
            self.circuit.assert_bool(index)

            # 根据index选择左右顺序
            left = self.circuit.select(index, sibling, current)
            right = self.circuit.select(index, current, sibling)

            # 哈希
            current = self.poseidon_hash([left, right])

        return current

    def sum_wires(self, wires: List[Wire]) -> Wire:
        """求和"""
        if not wires:
            return self.circuit.constant(0)

        result = wires[0]
        for w in wires[1:]:
            result = self.circuit.add(result, w)
        return result

    def product_wires(self, wires: List[Wire]) -> Wire:
        """求积"""
        if not wires:
            return self.circuit.constant(1)

        result = wires[0]
        for w in wires[1:]:
            result = self.circuit.mul(result, w)
        return result

    def build(self) -> Circuit:
        """返回构建的电路"""
        return self.circuit
