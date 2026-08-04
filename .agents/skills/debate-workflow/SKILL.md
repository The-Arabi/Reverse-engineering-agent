---
name: debate-workflow
description: Use when the user wants to resolve conflicting findings between analysis agents, validate hypotheses through structured debate, or get a second opinion on analysis conclusions. Triggers on debate, disagree, conflicting, second opinion, challenge finding, or consensus.
---

# Debate Workflow Skill

Use `re_debate` to run structured multi-agent debates that challenge, defend, and judge conflicting analysis findings.

## How It Works

The debate follows a 3-phase protocol:
1. **Assertion** — Agent A presents their finding
2. **Challenge** — Agent B identifies weaknesses and alternatives
3. **Defense** — Agent A responds to the challenge
4. **Verdict** — Independent judge rules: supported, challenged, or inconclusive

## When to Use

- Two agents disagree on a finding (e.g., "AES encryption" vs "XOR obfuscation")
- You want to validate a hypothesis before storing it as a fact
- You need a structured way to weigh conflicting evidence
- The user asks for a "second opinion" on analysis results

## Usage

```python
re_debate(
    topic="What encryption does the binary use?",
    assertions=[
        {
            "assertion": "The binary uses AES encryption based on S-box patterns found at 0x402000",
            "agent_id": "binary_agent",
            "agent_name": "Binary Agent",
            "agent_type": "binary_analysis",
            "context": "S-box constants at 0x402000 match AES specification. Round key schedule visible in disassembly at 0x401200."
        },
        {
            "assertion": "The binary uses XOR-based obfuscation, not AES",
            "agent_id": "cpu_agent",
            "agent_name": "CPU Agent",
            "agent_type": "cpu_analysis",
            "context": "Disassembly shows repeated XOR 0xAA operations on data buffers. No AESENC/AESDEC instructions found."
        }
    ],
    max_rounds=3
)
```

## Interpreting Results

- `final_consensus: "consensus"` — agents agree after debate
- `final_consensus: "divergent"` — agents still disagree
- `final_consensus: "inconclusive"` — not enough evidence either way
- `final_confidence` — 0.0 to 1.0, how confident the verdict is
- `key_disagreements` — list of unresolved points
- Each round has a `verdict`: "supported", "challenged", or "inconclusive"

## After Debate

If consensus is reached, store the agreed finding:
```
kb_add_fact(title="Binary uses AES-128", description="...", confidence=0.85, tags=["crypto"])
```

If divergent, store both as hypotheses for further investigation:
```
kb_add_hypothesis(title="Possible AES encryption", ..., confidence=0.6)
kb_add_hypothesis(title="Possible XOR obfuscation", ..., confidence=0.5)
```
