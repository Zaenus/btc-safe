```
  BIP: ?
  Layer: Consensus (soft fork)
  Title: Witness Version 3: ML-DSA-65 Post-Quantum Outputs
  Author: Zaenus <zaenus@users.noreply.github.com>
  Status: Draft
  Type: Specification
  Created: 2026-11-12
  License: MIT
  Discussion: https://delvingbitcoin.org/t/bip-draft-witness-version-3-ml-dsa-65-post-quantum-key-path-spending/2422
  Requires: 141, 173, 341, 350
```

## Abstract

This document proposes witness version 3 outputs that are spent with ML-DSA-65
(FIPS 204) post-quantum signatures. An output commits to a tagged hash of a
one-byte key type and an ML-DSA-65 public key; it is encoded as a bech32m
address starting with `bc1r`. Spending reveals the public key and a signature
over a BIP-341-style signature message.

Unlike every output type in use today, a witness v3 output **stays
quantum-resistant after its public key and signatures have been revealed**.
The hash commitment keeps outputs small; it is not what provides the security.

## Motivation

Bitcoin's ECDSA and Schnorr signatures over secp256k1 can be broken by Shor's
algorithm on a cryptographically relevant quantum computer (CRQC). Two kinds of
attack matter:

* **Long-exposure attacks** target public keys that are already on-chain: P2PK
  outputs, Taproot outputs (whose output key is in the scriptPubKey), and any
  address that has been spent from or reused. BIP-361 cites an estimate that
  more than 34% of all bitcoin had an exposed public key as of March 2026.
* **Short-exposure attacks** target a key revealed by a spend that is still in
  the mempool. A fast enough CRQC could derive the private key and replace the
  transaction before it confirms. This affects *every* output type spent with
  secp256k1, including never-reused P2PKH/P2WPKH.

### Why this has to happen before a CRQC exists

It is tempting to wait until a CRQC is demonstrated. That would be too late:

1. **Activation takes years.** Recent soft forks took several years from first
   proposal to activation, and wallets, exchanges and hardware vendors need
   time after that to ship support.
2. **Migration is limited by block space.** A typical 1-input, 1-output move
   from P2WPKH to a witness v3 output weighs 486 WU, so a block fits about
   8,200 of them. Every 10 million UTXOs therefore needs about 1,200 completely
   full blocks (roughly 8.4 days of *all* block space); at a realistic share of
   block space it takes months. The UTXO set has held well over 100 million
   entries in recent years.
3. **Coins that do not move in time stay exposed.** A destination must exist,
   be activated and be widely supported *before* the threat, or holders have
   nowhere safe to move to.

### Why "hide the key behind a hash" is not enough

P2WPKH also commits to a hash of a public key, but its security depends on the
key staying hidden. This proposal does not:

| Situation | P2WPKH / P2PKH | Witness v3 (this BIP) |
|---|---|---|
| Unspent, never used | safe (key hidden) | safe |
| Spend waiting in the mempool | **exposed** (short-exposure attack) | safe |
| After a spend, remaining/reused coins | **exposed** (long-exposure attack) | safe |
| Address reuse | **exposed** after first spend | safe from quantum attack (still bad for privacy) |

Because security does not depend on secrecy, the commitment only exists to keep
outputs to 34 bytes instead of carrying the 1,952-byte key.

## Specification

### Constants

| Name | Value |
|---|---|
| Witness version | 3 |
| Commitment tag | `"PQKeyCommit"` |
| Sighash tag | `"PQSighash"` |
| FIPS 204 context, transactions | `"bitcoin:pq:tx"` (13 bytes ASCII) |
| Key type `0x01` | ML-DSA-65: 1,952-byte public key, 3,309-byte signature |

`TaggedHash(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)` as in BIP-340.

### Outputs and addresses

```
key_blob     = key_type || public_key            (1 + 1,952 bytes for ML-DSA-65)
commitment   = TaggedHash("PQKeyCommit", key_blob)
scriptPubKey = OP_3 OP_PUSHBYTES_32 <commitment>  (hex: 53 20 <32 bytes>)
```

The address is the BIP-350 bech32m encoding of witness version 3 and the
32-byte commitment. Version 3 is the bech32 character `r`, so addresses start
with `bc1r` (mainnet), `tb1r` (testnet/signet) or `bcrt1r` (regtest). Example
(test vector key 1):

```
commitment   1db5ddad54116455f0ffe1a707435e38b1d5f1bf23fb34686da1a4f6d3f1effa
scriptPubKey 53201db5ddad54116455f0ffe1a707435e38b1d5f1bf23fb34686da1a4f6d3f1effa
mainnet      bc1rrk6amt25z9j9tu8luxnsws678zcatudly0ang6rd5xj0d5l3alaq9ar8vj
testnet      tb1rrk6amt25z9j9tu8luxnsws678zcatudly0ang6rd5xj0d5l3alaqj44gka
```

Witness version 2 (`bc1z`) is used by BIP-360 (P2MR).

### Spending rules

When an input spends a native output whose scriptPubKey is a witness version 3
program, the following rules apply. Witness v3 programs are **not** executed as
Script, so Script limits such as the 520-byte stack element limit do not apply;
the exact sizes below do.

1. The input's scriptSig must be empty.
2. If the witness program is not 32 bytes, the spend succeeds. (Reserved for
   future soft forks, as BIP-341 does for witness v1.)
3. If the witness stack has at least two elements and the first byte of the last
   element is `0x50`, that element is the *annex* and is removed (BIP-341 rule).
4. At least one element must remain. Call the last one `key_blob`.
5. `key_blob` must be non-empty and `TaggedHash("PQKeyCommit", key_blob)` must
   equal the witness program. Otherwise fail.
6. Let `key_type = key_blob[0]`. If `key_type` is `0x50`, fail. If `key_type`
   is not defined by this or a later BIP, the spend succeeds whatever the other
   stack elements are (upgrade hook, see below).
7. For `key_type = 0x01` (ML-DSA-65):
   1. The stack must be exactly `[signature, key_blob]`, and
      `public_key = key_blob[1:]` must be exactly 1,952 bytes.
   2. If the signature is 3,309 bytes, `hash_type = 0x00` (SIGHASH_DEFAULT). If
      it is 3,310 bytes, `hash_type` is its last byte, which is removed; it must be
      one of `0x01, 0x02, 0x03, 0x81, 0x82, 0x83`. Any other length fails.
   3. `msg = TaggedHash("PQSighash", 0x00 || SigMsg(hash_type, 0))`, where
      `SigMsg` is exactly as defined in BIP-341 (it commits to the annex when
      present). If `hash_type & 3 == SIGHASH_SINGLE` and there is no output with
      the input's index, fail.
   4. `ML-DSA.Verify(public_key, msg, signature, ctx = "bitcoin:pq:tx")` (FIPS 204
      Algorithm 3, "pure" ML-DSA) must succeed.

`0x50` can never be used as a key type. A two-element stack whose last element
begins with `0x50` is parsed as `[signature, annex]`, and rule 6 rejects
`0x50` explicitly in every other case, so an output committing to it is
unspendable.

**P2SH-wrapped witness v3 programs** (a P2SH redeemScript of the form `OP_3
<32 bytes>`) are not subject to these rules and remain unencumbered, as BIP-341
does for witness v1. They are non-standard, and wallets must never create them.

### Key types and upgrades

The key type byte lets later soft forks add signature schemes to witness v3
without using up another witness version (only versions 2-16 remain). Because
unknown key types succeed under rule 6, and the stack shape is only checked
per key type (rule 7), a future key type may use any number of witness
elements before its `key_blob`. A future soft fork can define, for
example, ML-DSA-44, SLH-DSA, FN-DSA or a hybrid secp256k1 + ML-DSA type by
adding rules for that byte. Such outputs must not be created before the
defining soft fork activates.

### Relay policy

Nodes should not relay or mine, by default, transactions with a witness v3
input that:

* has an annex;
* uses an undefined key type; or
* spends a witness v3 program that is not 32 bytes.

The standard transaction weight limit (400,000 WU) allows at most 73 ML-DSA-65
inputs per transaction.

### Sizes and validation cost

| Component | Bytes | Weight |
|---|---|---|
| Output (amount + script) | 43 | 172 WU |
| Input, non-witness part | 41 | 164 WU |
| Input witness (count, sig, key_blob with length prefixes) | 5,269 | 5,269 WU |
| **Input total** | | **5,433 WU (~1,358 vB)** |

For comparison, a Taproot key-path input weighs 230 WU. A 1-input, 2-output
transaction is about 1,455 vB, and a block holds at most about 736 ML-DSA-65
inputs. Each input performs exactly one ML-DSA-65 verification, so no separate
signature-operation budget is defined. Benchmarks of ML-DSA-65 verification in
Bitcoin Core are still needed to confirm that validation time per weight unit
stays below current worst cases.

## Wallet considerations

* **Never create mainnet witness v3 outputs before activation.** Until then,
  consensus treats them as anyone-can-spend. Wallets that implement BIP-350 can
  already *send* to `bc1r` addresses, so recipients must not hand them out.
* **Keys.** The 32-byte FIPS 204 key generation seed is the private key.
  Wallets should derive it from a BIP-39 seed. ML-DSA has no public
  (non-hardened) derivation, so there are no xpubs: watch-only wallets need each
  public key exported individually. The reference implementation uses
  hardened-only, SLIP-10-style HMAC-SHA512 derivation with path
  `m/3'/coin'/account'/index'`; the purpose number is a placeholder.
* **Address reuse** does not weaken quantum resistance, but it still harms
  privacy, so wallets should continue to use fresh addresses.
* **Signing devices** must show the full transaction. Because the signature
  message commits to every input's amount and scriptPubKey, devices do not
  need to trust a host about input values.
* **Message signing** (off-chain) must use a different FIPS 204 context. The
  reference implementation uses `"bitcoin:pq:msg"`, so a message signature can
  never be valid as a transaction signature.
* **PSBT.** Until field types are assigned, the reference implementation
  carries the key blob, signature and derivation path under the proprietary
  type `0xFC` with identifier `"safebtc"`; finalized inputs use the standard
  `PSBT_IN_FINAL_SCRIPTWITNESS`.

## Rationale

**Why commit to a hash at all?** Size. Putting the 1,952-byte key in the output
would make every output about 45 times larger and grow the UTXO set
accordingly. Security does not depend on the key staying secret (see
Motivation).

**Why a tagged hash with a key type?** Domain separation from every other use of
SHA-256 in Bitcoin, and algorithm agility without spending witness versions.
A 32-byte commitment gives 128-bit preimage resistance against Grover's
algorithm. Quantum collision search (Brassard-Hoyer-Tapp) would in theory take
about 2^85 operations *and* as much quantum memory, which is not considered
practical; collisions also only matter when another party contributes key
material, which a single-key output does not allow.

**Why BIP-341's signature message instead of BIP-143's?** BIP-143 commits only
to the amount of the input being signed, which allowed a fee-lying attack on
hardware wallets. BIP-341's `SigMsg` commits to every input's amount and
scriptPubKey and supports the annex. Reusing it byte for byte lets
implementations share Taproot code; using the distinct tag `"PQSighash"`
guarantees a Taproot sighash never equals a witness v3 sighash.

**Why FIPS 204 context strings, and why "pure" ML-DSA?** A non-empty context
makes it impossible to replay a signature produced by other software using the
same key. The message is already a 32-byte hash, so HashML-DSA (pre-hash) adds
nothing.

**Why ML-DSA-65 and not ML-DSA-44?** This is an open question raised on Delving
Bitcoin. ML-DSA-44 (NIST category 2) inputs weigh about 3,904 WU instead of
5,433 (28% smaller, about 1,024 inputs per block instead of 736). ML-DSA-65
(category 3) gives more margin against future cryptanalysis of lattices, which
are newer than the assumptions Bitcoin relies on today. The key type registry
makes adding ML-DSA-44 a one-line change; feedback is requested.

**Alternatives considered:**

* **P2MR (BIP-360) plus a post-quantum signature opcode in a script leaf.** This
  gives full Script flexibility (multisig, timelocks, backup leaves) and can
  hide unused alternatives. For the common single-key case it costs more
  (control block plus a script containing the key) and requires changes to the
  Script interpreter. The two are complementary: P2MR for scripts, witness v3
  for single-key spends. The `key_blob` encoding defined here could be reused by
  such an opcode.
* **Hybrid secp256k1 + ML-DSA.** Hedges against a classical break of lattice
  cryptography for about 100 extra bytes per input (Schnorr key and signature). It can be added later as its
  own key type.
* **SLH-DSA (FIPS 205).** Relies only on hash functions (the most conservative
  assumption) and has 32-byte public keys, but signatures are 7,856 bytes or
  more. A good candidate for a future key type or a P2MR backup leaf.
* **FN-DSA / Falcon.** Much smaller (897-byte keys, about 666-byte signatures)
  but signing uses floating-point arithmetic that is hard to implement safely on
  signing devices.
* **Signature aggregation.** Out of scope. SNARK-based aggregation needs
  hash-based (STARK-style) proofs, since pairing-based SNARKs such as Groth16
  are themselves broken by a CRQC, and Bitcoin consensus cannot depend on a
  trusted setup. See `docs/research/signature-aggregation.md`.

## Relationship to other proposals

* **BIP-360 (P2MR, witness v2)** removes Taproot's quantum-vulnerable key path.
  This BIP adds a post-quantum key spend; they can be deployed independently.
* **BIP-361 (Post Quantum Migration and Legacy Signature Sunset)** describes how
  legacy signatures could be phased out once a post-quantum output type exists.
  This BIP is one candidate for that output type.

## Backward compatibility

This is a soft fork. Nodes that do not implement it treat witness v3 outputs as
anyone-can-spend and accept any spend of them. After activation, upgraded nodes
enforce the rules above. As with any soft fork, users must not create such
outputs on mainnet before activation.

## Deployment

To be determined. No activation mechanism or signalling bit is proposed yet.

## Test vectors

`0001-test-vectors.json`, generated by `tools/generate_bip_vectors.py`, contains:

* **keys**: seed, public key, commitment, scriptPubKey and addresses on each
  network;
* **derivation**: BIP-39 mnemonic and path to key generation seed;
* **sighash**: `SigMsg` and sighash for every hash type, with and without annex;
* **spends**: complete signed transactions, each marked valid or invalid,
  standard or not, and whether it succeeded through an upgrade hook. Cases
  include a valid spend for each of the seven hash types; the annex; the wrong
  FIPS 204 context; the wrong key; empty and wrong-sized witnesses, key blobs,
  public keys and signatures; invalid hash type bytes; SIGHASH_SINGLE without a
  matching output (signed over the message a lenient implementation would
  compute); non-empty scriptSig; key type `0x50` with and without an annex;
  and the upgrade hooks.

Signatures are deterministic FIPS 204 signatures produced by an independent
implementation (dilithium-py) and verified by the OpenSSL-backed reference
implementation. The sighash code is also checked against the official BIP-341
vectors. Those contain no annex cases, so the annex path is covered only by
this BIP's own vectors; it was also compared by hand with Bitcoin Core's
test-framework `TaprootSignatureMsg`.

## Reference implementation

https://github.com/Zaenus/btc-safe: see `src/safe_btc/consensus.py` (spending
rules), `transaction.py` (signature message), `pq_addresses.py` (outputs and
addresses) and `psbt.py`.

## Open questions

1. ML-DSA-44 vs ML-DSA-65 as the first defined key type.
2. Whether a hybrid key type should be defined from the start.
3. Validation benchmarks in Bitcoin Core and whether a per-block verification
   limit is needed.
4. Whether ML-DSA spends should get a different witness discount.
5. BIP-43 purpose number and PSBT field type assignments.

## Acknowledgments

Thanks to the reviewers on Delving Bitcoin and the bitcoin-dev mailing list
whose feedback shaped this revision.

## Copyright

This document is licensed under the MIT License.
