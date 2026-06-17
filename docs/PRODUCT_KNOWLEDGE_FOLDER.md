# Product Knowledge Folder

Current phase: simplified `IncidentReadAndWhisper` runtime.

`local_knowledge/` is the only normal runtime knowledge source. It is private, ignored by git, externally reviewed outside the app, and validated before use.

Required files:

```text
local_knowledge/
  README.md
  manifest.yaml
  service_catalog.yaml
  command_registry.yaml
  decision_moments.jsonl
  verifier_regressions.jsonl
  rejected_entities.jsonl
  stale_question_patterns.jsonl
```

Normal product runs load `service_catalog.yaml`, `command_registry.yaml`, and `decision_moments.jsonl`. Support files may add verifier guardrails only when validated; they do not override current incident evidence.

Validate:

```bash
python -m ic_copilot.cli validate-knowledge local_knowledge
python -m ic_copilot.cli knowledge-status local_knowledge
```

Bootstrap from committed contract seed data when needed:

```bash
python scripts/bootstrap_product_knowledge.py \
  --output local_knowledge \
  --source-contract data/contract \
  --reviewed-by "jcruzlopez" \
  --review-method "externally reviewed outside app" \
  --apply
```

The validator rejects missing manifests, unreviewed memory, unsafe commands, commands without human approval, secret-looking values, and forbidden runtime paths.
