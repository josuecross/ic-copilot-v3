# Data Source Of Truth

Current phase: Phase 1.36C.

- `local_knowledge/`: private runtime knowledge. Ignored by git.
- `data/product_knowledge_example/`: committed example of the runtime knowledge contract.
- `data/contract/`: contract tests and bootstrap seed data. Not a hidden product fallback.
- `data/sample/`: demo and smoke snippets.
- `data/personal_regression/`: committed regression fixtures for safety and usefulness.
- `.ic_copilot/`: local generated state, traces, reports, and databases.

Historical dev archives were removed from the active repo. Normal product code must not load private curation folders, previous incident packages, generated archives, prompt-variant archives, or draft files as runtime knowledge.
