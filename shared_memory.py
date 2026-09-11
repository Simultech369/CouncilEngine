"""
Cross-Council Knowledge Sharing & Invariant Learning Mesh
Council Engine - Multi-Agent Collaborative Evolution
Bridges to the Formal Governance Rules and Working Best Practices engine.
"""

from governance_rules import (
    load_formal_rules,
    save_formal_rules,
    load_working_practices,
    save_working_practices,
    record_working_practice,
    update_practice_effectiveness,
    FormalGovernanceEngine,
    get_complete_invariants_and_practices_context
)

def record_learned_invariant(domain: str, invariant_rule: str):
    """Adds a working best practice or triggers rule proposal."""
    record_working_practice(category=domain, title=f"Learned invariant in {domain}", guideline=invariant_rule)

def get_invariants_prompt_context(domain_focus: str = "general") -> str:
    """Returns the clearly partitioned context containing Formal Rules & Working Practices."""
    return get_complete_invariants_and_practices_context()
