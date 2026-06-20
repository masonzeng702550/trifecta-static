# Trifecta-Static

**Static detection of the _lethal trifecta_ in AI-agent codebases — before they ship.**

An LLM agent becomes dangerous the moment a single trust boundary can do all three of:

| Leg | Capability | Example tools |
|----|-------------|---------------|
| **A — ingress** | read untrusted / external input | `read_email`, `fetch_url`, `search_web` |
| **B — private** | read private / sensitive data | `get_secret`, `read_file`, `query_db` |
| **C — egress** | send data out of the boundary | `http_post`, `send_email`, `post_webhook` |

When A, B and C co-exist, a successful prompt injection stops being a nuisance and
becomes near-guaranteed data exfiltration: attacker text read via A steers the agent
to read secrets via B and ship them out via C. (Mental model: Simon Willison's
[lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/).)

Filtering prompt-injection text is an unwinnable arms race. Trifecta-Static defends one
layer lower — **capabilities and data flow** — and makes "are the three legs reachable in
one trust boundary?" a property you can check statically, in CI, on a pull request, with
no running agent and no payload to craft.

> Trifecta-Static is the cheapest, left-most line of defence. It does **not** replace
> dynamic red-teaming (e.g. Promptfoo) or runtime egress monitoring — it complements them,
> and it is honest about its static blind spots (see [Limitations](#limitations)).

## What it does

1. **Parses** tool / agent definitions across frameworks into one framework-agnostic IR —
   LangChain/LangGraph, LlamaIndex, CrewAI, AutoGen, FastMCP servers, and raw
   MCP / OpenAI / Anthropic tool schemas.
2. **Classifies** each tool into the A / B / C legs with signature rules (tool name,
   description/schema fields, and the functions the implementation actually calls), with an
   optional, off-by-default LLM-assisted layer.
3. **Infers trust boundaries** (default = one agent; sub-agents fold in unless an isolation
   pattern — dual-LLM, quarantine, human-approval gate — cuts the boundary).
4. **Analyzes**:
   - *shallow* — pure co-location: does `A ∧ B ∧ C` hold in a boundary? (decidable, 100 % recall)
   - *deep* — intra-procedural taint: does a private seed actually reach a non-allowlisted
     egress sink? Upgrades `co-located` → `confirmed`.
5. **Reports** findings — each anchored to `file:line`, with the three legs as related
   locations and concrete mitigations — as a coloured table, JSON, or **SARIF 2.1.0** for
   GitHub Code Scanning / GitLab. A non-zero exit code makes it a CI gate.

## Install

```bash
pip install -e .            # core analysis is dependency-free
pip install -e ".[llm]"     # optional LLM-assisted classifier
pip install -e ".[dev]"     # test tooling
```

Requires Python ≥ 3.9.

## Usage

```bash
trifecta scan <path> [options]

  --framework {auto|langchain|llamaindex|mcp|openai|anthropic|crewai|autogen}
                          repeatable; default auto
  --format    {table|json|sarif}        default table
  --depth     {shallow|deep}            shallow = co-location; deep = + taint
  --llm-classify                        enable optional LLM-assisted classification
  --egress-allowlist <file>             trusted egress hosts, one per line
  --baseline <file>                     suppress findings recorded in a baseline
  --write-baseline <file>               snapshot current findings as a baseline
  --fail-on  {critical|high|medium|low|info}   CI gate threshold; default high
  -o, --output <file>
  --no-color
```

Examples:

```bash
# Deep scan, SARIF for Code Scanning, fail the build on high+ findings
trifecta scan ./agent --depth deep --format sarif -o trifecta.sarif --fail-on high

# Adopt gradually: record existing findings, then only fail on new ones
trifecta scan ./agent --write-baseline trifecta-baseline.json
trifecta scan ./agent --baseline trifecta-baseline.json --fail-on medium
```

### Sample output

```
 CRITICAL  TRIFECTA-0001  lethal-trifecta/confirmed  (confirmed)
    boundary: support_assistant [agent]  agent.py:7
      A ingress    read_email   tools.py:13  conf=0.90 [signature]
      B private    get_secret   tools.py:22  conf=0.90 [signature]
      C egress     http_post    tools.py:30  conf=0.90 [signature]
      ↳ data flow: private seed reaches egress payload
        path: tools.py:28 → tools.py:29 → tools.py:30
    blast radius: secrets can be sent to a non-allowlisted egress destination
    fix: move http_post into a separate sub-agent with no private-data access
```

## Severity model

| Verdict | Condition | Severity |
|---|---|---|
| `confirmed` | private data reaches a non-allowlisted egress sink (deep flow proven) | **critical** |
| `confirmed` | same, but egress is allowlisted / gated | **high** |
| `co-located` | all three legs in one boundary, egress non-allowlisted | **high** |
| `co-located` | all three legs, egress allowlisted / gated | **medium** |
| `near-miss` | only two of three legs present | **info** |

## CI integration

```yaml
# .github/workflows/trifecta.yml
- run: pip install -e .
- run: trifecta scan ./agent --depth deep --format sarif -o trifecta.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: trifecta.sarif }
```

## Limitations

Static analysis has a coverage ceiling, and the tool states it rather than hiding it:

- **Dynamically registered tools** (decided at runtime / by config / by a remote service) are
  invisible to static parsing → possible false negatives.
- **Trust-boundary inference** can be too coarse (merging genuinely isolated components → false
  positive) or too fine (splitting shared ones → false negative). It is deliberately
  conservative and user-overridable.
- **Deep taint** is intra-procedural with limited inter-procedural reach; aliasing, reflection
  and deep third-party flows are marked `analysis-incomplete`, never silently dropped.
- This is one layer of defence in depth. Pair it with dynamic testing and runtime monitoring.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The fixture corpus under `tests/fixtures/` doubles as living documentation: known-positive
(`tf-*`) and known-safe (`safe-*`) agent configs that pin the recall/precision contract.

## License

Apache-2.0. See [LICENSE](LICENSE).
