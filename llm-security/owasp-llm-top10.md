# OWASP Top 10 for LLM Applications 2025

> Reference summary of the 2025 release. Authoritative source is genai.owasp.org — this file is a quick lookup; cite the upstream page in reports. Authorized testing only.

## TL;DR
- Maintained by OWASP's GenAI Security Project (https://genai.owasp.org/). Annual revisions; the 2025 edition (released Nov 2024) is the current standard.
- Ten risk categories cover input handling, output handling, supply chain, sensitive data, plugin/tool design, agency, overreliance, model theft, model DoS, and training data poisoning.
- Per-risk template: short description, common attack patterns, control recommendations, related CWEs / NIST AI RMF mappings.

## LLM01 — Prompt Injection
- **Description**: attacker manipulates the LLM's behavior by injecting instructions into input (direct) or into content the LLM processes (indirect, RAG, web fetch).
- **Patterns**: instruction override, role play, encoded payloads, indirect via documents.
- **Controls**: privilege separation, output schema validation, narrow tool scopes, allow-list URLs, adversarial eval.
- See [./prompt-injection.md](./prompt-injection.md).

## LLM02 — Insecure Output Handling
- **Description**: downstream system trusts LLM output without validation — leads to XSS, SQLi, command injection, server-side template injection, SSRF.
- **Patterns**: LLM emits HTML / SQL / shell / template that the application renders / executes / passes verbatim.
- **Controls**: treat output as untrusted; strict schema validation; context-aware output encoding (HTML escape, parameterised SQL, never `eval()`).
- CWE-79, CWE-89, CWE-78, CWE-95, CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine).

## LLM03 — Training Data Poisoning
- **Description**: adversary contributes to training / fine-tuning data to inject backdoors or bias outputs.
- **Patterns**: open-data scraping ingests adversarial URLs; supply-chain attack on a labeling vendor; insider compromise.
- **Controls**: data provenance (signed dataset manifests), differential testing of pre- and post-fine-tune behavior, RLHF / RLAIF eval suites, adversarial inputs in red-team eval, dataset audit by ML team.

## LLM04 — Model Denial of Service
- **Description**: resource-exhaustion attacks — context-window flood, recursive tool calls, complex prompts that drive long generation, embedding-space attacks.
- **Patterns**: huge user input, intentionally pathological token sequences, RAG-triggered fetches that cascade, multi-agent loops.
- **Controls**: per-request token budget, per-user rate limit, max-output guard, agent step budget with circuit breakers, queue-level priority + isolation.
- CWE-400 Uncontrolled Resource Consumption.

## LLM05 — Supply Chain Vulnerabilities
- **Description**: compromise of pre-trained models, libraries (`transformers`, `langchain`), or model registries (Hugging Face) propagates into the LLM app.
- **Patterns**: malicious model on a public registry (loaded via `pickle` deserialization), typo-squatted package, compromised LoRA adapter, dataset with hidden poisoning.
- **Controls**: SBOM for ML deps + model artefacts; pin models by hash; signed model weights (Sigstore for models — see [../cicd-supply-chain/sbom-sigstore.md](../cicd-supply-chain/sbom-sigstore.md)); load adapters / weights through safe formats (`safetensors`, not `pickle`).

## LLM06 — Sensitive Information Disclosure
- **Description**: LLM emits secrets from training data, RAG context, or memory that the user shouldn't see.
- **Patterns**: PII memorisation (especially from internet-scraped training sets), RAG context leakage across tenants, prompt-injection–driven exfil.
- **Controls**: differential privacy in training (where feasible), per-tenant RAG isolation, output PII / secret scanning, model unlearning where regulator demands (right to be forgotten), red-team membership-inference attacks.
- CWE-200 Information Exposure.

## LLM07 — Insecure Plugin / Tool Design
- **Description**: LLM-callable plugins/tools accept arbitrary structured input from the model without validating it as untrusted.
- **Patterns**: plugin's HTTP endpoint accepts any URL → SSRF; plugin's SQL tool accepts raw SQL → SQLi; plugin's file tool accepts path traversal → arbitrary file read.
- **Controls**: parameterised schemas (allow-list of fields, types, ranges); no free-text arguments where a structured field would do; authn per plugin tied to the *user*, not the LLM service; output validation back to the LLM (don't pipe error stacks straight back).
- Maps to CWE-20 Improper Input Validation, CWE-918 SSRF, CWE-89 SQLi.

## LLM08 — Excessive Agency
- **Description**: LLM-driven agent has too many tools, too much permission, or executes irreversible operations without human-in-the-loop.
- **Patterns**: agent that can `send_email`, `transfer_money`, `delete_record` without confirmation; agent with cross-tenant tool access; agent with persistent memory that accumulates instructions over time.
- **Controls**: least privilege per tool; per-tool authorisation tied to the requesting user; human-confirm for irreversible / high-impact actions; agent step budget; auditable action log.

## LLM09 — Overreliance
- **Description**: app or user trusts LLM output as authoritative for tasks where it isn't (code generation, legal/medical advice, security analysis).
- **Patterns**: developer ships LLM-generated code without review; clinician uses LLM diagnosis without verification; security tool relies on LLM to triage alerts.
- **Controls**: confidence calibration to user; UI affordances signalling AI-generated; mandatory human review for high-stakes domains; eval that surfaces failure modes (hallucination rate, factual accuracy benchmark).

## LLM10 — Model Theft
- **Description**: extraction of weights, training data, or capabilities of a proprietary model.
- **Patterns**: API distillation (query the model heavily to train a replica); insider exfil of weights from training infra; side-channel via timing.
- **Controls**: per-customer query budget + watermarking; weights stored in HSM-equivalent enclaves; access auditing on weight stores; API responses that resist distillation (sampling controls, response perturbation in research settings).

## Mapping to other frameworks

| OWASP LLM | NIST AI RMF | MITRE ATLAS | CWE |
| --- | --- | --- | --- |
| LLM01 Prompt Injection | GOVERN, MEASURE | AML.T0051 LLM Prompt Injection | CWE-20, CWE-77 |
| LLM02 Insecure Output Handling | MAP, MEASURE | AML.T0050 Output Manipulation | CWE-79/89/78/95 |
| LLM03 Training Data Poisoning | MAP, MEASURE | AML.T0019 Backdoor ML Model | CWE-1357 |
| LLM04 Model DoS | MEASURE, MANAGE | AML.T0029 Denial of ML Service | CWE-400 |
| LLM05 Supply Chain | GOVERN, MAP | AML.T0010 ML Supply Chain Compromise | CWE-1357 |
| LLM06 Sensitive Info Disclosure | MEASURE | AML.T0024 Membership Inference | CWE-200 |
| LLM07 Insecure Plugin / Tool | MAP, MEASURE | AML.T0053 LLM Plugin Compromise | CWE-20, CWE-918 |
| LLM08 Excessive Agency | GOVERN, MANAGE | AML.T0048 External Harms (Agentic) | CWE-269 |
| LLM09 Overreliance | GOVERN, MANAGE | AML.T0048 External Harms | — |
| LLM10 Model Theft | MEASURE | AML.T0044 ML Model Stealing | CWE-200 |

## Sources
- OWASP GenAI Security Project: https://genai.owasp.org/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
- NIST AI Risk Management Framework (AI RMF 1.0): https://www.nist.gov/itl/ai-risk-management-framework
- NIST AI 100-2 Adversarial Machine Learning Taxonomy: https://csrc.nist.gov/pubs/ai/100/2/e2025/final
- MITRE ATLAS: https://atlas.mitre.org/
- OWASP LLM AI Security & Governance Checklist: https://owasp.org/www-project-top-10-for-large-language-model-applications/
