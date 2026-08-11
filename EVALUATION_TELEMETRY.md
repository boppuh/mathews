# Version-bound evaluation telemetry

Task 7.3 records reproducible retrieval and prompt evaluations without turning
telemetry into workflow authority. Every record is bound to one terminal Hermes
run, one immutable evaluation contract, one retrieval generation, one prompt
template version, one policy version, and one explicit model version.

## Frozen inputs

An evaluation contract versions the minimum run count, quality threshold,
maximum average cost, regression pass-rate threshold, and the exact regression
case identifiers. Contract content has a deterministic fingerprint and a
lineage/version predecessor chain. Only one version in a lineage may be active.

Each run evaluation stores:

- the ordered retrieval set with evidence and derivative IDs, source hashes,
  envelope hashes, chunk hashes, ordinals, and scores;
- retrieval generation, index, chunker, and verifier versions;
- prompt template and policy IDs and integer versions;
- model provider, name, and exact model version;
- input, output, cached, and total tokens plus cost in integer micro-US-dollars;
- quality outcome and bounded score; and
- a complete result for every frozen regression case.

The record has a canonical fingerprint. Replaying the same run is idempotent;
changing any bound input or result fails closed.

## Reproducible comparison

`EvaluationTelemetryService.compare` groups only evaluations from the exact
contract version and separates results by prompt, retrieval, and model versions.
It computes run count, average quality, average cost, and regression pass rate,
then reports whether the frozen thresholds are satisfied. The result is evidence
for later human-governed promotion; it cannot activate prompts, rules, policies,
permissions, or workflow state.
