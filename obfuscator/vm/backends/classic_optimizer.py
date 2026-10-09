"""Conservative Classic-only optimizations over physical handler layouts."""
from __future__ import annotations

from dataclasses import replace

from .handler_layout import PhysicalFunction
from .runtime_layout import iter_functions


def _jump_target(function: PhysicalFunction, index: int) -> int | None:
    """Return a valid in-function target for one physical jump."""
    if not 0 <= index < len(function.code):
        return None
    instruction = function.code[index].instruction
    if instruction.operation != "JUMP":
        return None
    target = index + 1 + instruction.sbx
    return target if 0 <= target < len(function.code) else None


def _redirect_jump_chains(function: PhysicalFunction) -> list[dict[str, object]]:
    """Bypass one semantically inert jump in a Classic physical function.

    Lua's ``JMP A`` may close upvalues, and Karity's graph/avalanche metadata
    gives an otherwise plain jump observable protection-state effects.  Those
    cases intentionally remain untouched.  Only a no-close, metadata-free
    jump to another no-close, metadata-free jump can be redirected.  The
    physical slot count remains unchanged, so routes and serializer PCs stay
    valid without a layout rebase.
    """
    events: list[dict[str, object]] = []
    for index, item in enumerate(function.code):
        instruction = item.instruction
        if instruction.operation != "JUMP":
            continue
        target = _jump_target(function, index)
        if target is None:
            events.append({
                "function": function.source.id, "pc": index,
                "kind": "jump-chain", "outcome": "rejected",
                "reason": "out-of-range-target",
            })
            continue
        target_item = function.code[target]
        target_instruction = target_item.instruction
        if target_instruction.operation != "JUMP":
            continue
        if instruction.a or target_instruction.a:
            events.append({
                "function": function.source.id, "pc": index,
                "kind": "jump-chain", "outcome": "rejected",
                "reason": "upvalue-close",
            })
            continue
        if item.avalanche or target_item.avalanche:
            events.append({
                "function": function.source.id, "pc": index,
                "kind": "jump-chain", "outcome": "rejected",
                "reason": "avalanche-boundary",
            })
            continue
        if item.graph_sites or target_item.graph_sites:
            events.append({
                "function": function.source.id, "pc": index,
                "kind": "jump-chain", "outcome": "rejected",
                "reason": "graph-boundary",
            })
            continue
        redirected = _jump_target(function, target)
        if redirected is None:
            events.append({
                "function": function.source.id, "pc": index,
                "kind": "jump-chain", "outcome": "rejected",
                "reason": "terminal-target",
            })
            continue
        replacement = instruction.with_bx(redirected - index - 1 + 131071)
        function.code[index] = replace(item, instruction=replacement)
        events.append({
            "function": function.source.id, "pc": index,
            "kind": "jump-chain", "outcome": "applied",
            "target": redirected,
        })
    return events


def optimize_layout(layout) -> tuple[dict[str, int], tuple[dict[str, object], ...]]:
    """Optimize each Classic physical function and return stable diagnostics."""
    events: list[dict[str, object]] = []
    instruction_count = 0
    for function in iter_functions(layout.functions):
        instruction_count += len(function.code)
        events.extend(_redirect_jump_chains(function))
    applied = sum(event["outcome"] == "applied" for event in events)
    return ({
        "before": instruction_count,
        "after": instruction_count,
        "jump_chain_redirects": applied,
        "jump_chain_rejections": len(events) - applied,
    }, tuple(events))
