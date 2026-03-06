"""Peephole optimizer -- runs on Stack IR before emission.

Scans for short sequences of stack operations that can be replaced with
fewer or cheaper opcodes.  Applies rules iteratively until a fixed point
is reached (no more changes).  Mirrors the TypeScript / Go peephole optimizer.

Port of ``compilers/go/codegen/optimizer.go``.
"""

from __future__ import annotations

from typing import Optional

from runar_compiler.codegen.stack import StackOp, PushValue

MAX_OPTIMIZATION_ITERATIONS = 100


def optimize_stack_ops(ops: list[StackOp]) -> list[StackOp]:
    """Apply peephole optimization to a list of stack ops."""
    # First, recursively optimize nested if-blocks
    current = [_optimize_nested_if(op) for op in ops]

    for _ in range(MAX_OPTIMIZATION_ITERATIONS):
        result, changed = _apply_one_pass(current)
        if not changed:
            break
        current = result

    return current


def _optimize_nested_if(op: StackOp) -> StackOp:
    if op.op == "if":
        optimized_then = optimize_stack_ops(op.then)
        optimized_else = optimize_stack_ops(op.else_ops) if op.else_ops else []
        return StackOp(
            op="if",
            then=optimized_then,
            else_ops=optimized_else,
        )
    return op


def _apply_one_pass(ops: list[StackOp]) -> tuple[list[StackOp], bool]:
    result: list[StackOp] = []
    changed = False
    i = 0

    while i < len(ops):
        # Try window-2 rules first
        if i + 1 < len(ops):
            replacement = _match_window2(ops[i], ops[i + 1])
            if replacement is not None:
                result.extend(replacement)
                i += 2
                changed = True
                continue

        result.append(ops[i])
        i += 1

    return result, changed


def _match_window2(a: StackOp, b: StackOp) -> Optional[list[StackOp]]:
    """Try to match a window-2 peephole rule.  Returns replacement list or None."""

    # PUSH x, DROP -> remove both (dead value elimination)
    if a.op == "push" and b.op == "drop":
        return []

    # DUP, DROP -> remove both
    if a.op == "dup" and b.op == "drop":
        return []

    # SWAP, SWAP -> remove both (identity)
    if a.op == "swap" and b.op == "swap":
        return []

    # PUSH 1, OP_ADD -> OP_1ADD
    if _is_push_bigint(a, 1) and _is_opcode_op(b, "OP_ADD"):
        return [StackOp(op="opcode", code="OP_1ADD")]

    # PUSH 1, OP_SUB -> OP_1SUB
    if _is_push_bigint(a, 1) and _is_opcode_op(b, "OP_SUB"):
        return [StackOp(op="opcode", code="OP_1SUB")]

    # PUSH 0, OP_ADD -> remove both (x + 0 = x)
    if _is_push_bigint(a, 0) and _is_opcode_op(b, "OP_ADD"):
        return []

    # PUSH 0, OP_SUB -> remove both (x - 0 = x)
    if _is_push_bigint(a, 0) and _is_opcode_op(b, "OP_SUB"):
        return []

    # OP_NOT, OP_NOT -> remove both (double negation)
    if _is_opcode_op(a, "OP_NOT") and _is_opcode_op(b, "OP_NOT"):
        return []

    # OP_NEGATE, OP_NEGATE -> remove both
    if _is_opcode_op(a, "OP_NEGATE") and _is_opcode_op(b, "OP_NEGATE"):
        return []

    # OP_EQUAL, OP_VERIFY -> OP_EQUALVERIFY
    if _is_opcode_op(a, "OP_EQUAL") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_EQUALVERIFY")]

    # OP_CHECKSIG, OP_VERIFY -> OP_CHECKSIGVERIFY
    if _is_opcode_op(a, "OP_CHECKSIG") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_CHECKSIGVERIFY")]

    # OP_NUMEQUAL, OP_VERIFY -> OP_NUMEQUALVERIFY
    if _is_opcode_op(a, "OP_NUMEQUAL") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_NUMEQUALVERIFY")]

    # OP_CHECKMULTISIG, OP_VERIFY -> OP_CHECKMULTISIGVERIFY
    if _is_opcode_op(a, "OP_CHECKMULTISIG") and _is_opcode_op(b, "OP_VERIFY"):
        return [StackOp(op="opcode", code="OP_CHECKMULTISIGVERIFY")]

    # OP_DUP, OP_DROP -> remove both
    if _is_opcode_op(a, "OP_DUP") and _is_opcode_op(b, "OP_DROP"):
        return []

    # OP_OVER, OP_OVER -> OP_2DUP
    if a.op == "over" and b.op == "over":
        return [StackOp(op="opcode", code="OP_2DUP")]

    # OP_DROP, OP_DROP -> OP_2DROP
    if a.op == "drop" and b.op == "drop":
        return [StackOp(op="opcode", code="OP_2DROP")]

    return None


def _is_push_bigint(op: StackOp, n: int) -> bool:
    if op.op != "push" or op.value is None:
        return False
    if op.value.kind != "bigint" or op.value.big_int is None:
        return False
    return op.value.big_int == n


def _is_opcode_op(op: StackOp, code: str) -> bool:
    return op.op == "opcode" and op.code == code
