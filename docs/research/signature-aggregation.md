# Research notes: aggregating post-quantum signatures

Status: research only. Nothing here is part of the BIP draft.

safe-btc 0.1 shipped a `MockSNARK` "aggregation" module and advertised
compressing 3,309-byte ML-DSA signatures into 192-byte proofs. It was removed in
0.2 because:

1. **The mock was forgeable.** Its `verify` never looked at signatures and
   trusted a prover-supplied commitment root, so a "proof" could be built for
   messages that were never signed.
2. **The headline numbers were wrong even as an illustration.** Public keys
   (1,952 bytes each) were still carried, so a single "aggregated" signature was
   about 66% of the original size, not 6%.
3. **The proof system it pointed to is not post-quantum.** Groth16, PLONK with
   KZG commitments and other pairing-based SNARKs rest on elliptic-curve
   discrete-log assumptions. A CRQC could forge their proofs, which would defeat
   the purpose.
4. **Trusted setups are unacceptable for Bitcoin consensus.** Whoever knows the
   setup's toxic waste could forge proofs for any statement.

## What a real design would need

* **A transparent, hash-based proof system** (STARKs or other FRI-based
  systems). These need no trusted setup and rely only on hash functions, but
  proofs are tens to hundreds of kilobytes. Aggregation only pays off across
  many signatures, which suggests block-level or very large transaction-level
  proofs rather than per-transaction proofs.
* **A circuit for ML-DSA verification** (NTT arithmetic mod q = 8,380,417 and
  SHAKE). SHAKE/Keccak is expensive inside arithmetic circuits; proving cost
  and prover latency for miners are open questions.
* **Public keys still have to be available,** unless outputs commit to keys in a
  way the proof can open, which changes the output format.
* **Consensus risk.** A STARK verifier in consensus is a large new attack
  surface. Any bug is a consensus-level inflation or theft bug.

## Alternatives that reduce size without SNARKs

* A **smaller parameter set or scheme** as an additional key type: ML-DSA-44
  (~28% smaller inputs) or FN-DSA (Falcon, about 1,560 bytes for key plus
  signature).
* **Fewer inputs** through consolidation and batching, which wallets can do
  today.
* **Cross-input key reuse:** when several inputs share a key, a future rule
  could let later inputs reference an earlier key_blob instead of repeating it
  (saving 1,953 bytes each). This needs no new cryptography.

## Further reading

* BIP-360 (P2MR) and BIP-361 (legacy signature sunset)
* Delving Bitcoin discussions on post-quantum signature sizes and hash-based
  signatures
