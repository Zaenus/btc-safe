# Changelog

## Unreleased

### Documentation
- The BIP draft and README now credit echelonresearch's April 2026 witness v3
  draft on Delving Bitcoin as prior work and list how this draft differs. The
  BIP no longer names that thread as its own discussion venue.
- The P2MR alternative is reassessed: the size difference is under 10 WU per
  input; the real trade-offs are Tapscript's 520-byte element limit versus
  witness v3's lack of a fallback leaf.
- Exposure figure updated to 7,159,718 BTC (35.6%) at block 975,029
  (ChainQuery weekly UTXO-set walk), alongside BIP-361's March estimate.

## 0.2.0 (2026-11-13)

This release fixes bugs that could lose funds, and revises the BIP draft after
community feedback. **Key files and addresses from 0.1 are not compatible and
should be discarded.** No 0.1 address was ever spendable, since witness v3 is
not active and 0.1 addresses had an invalid checksum.

### Fixed: could lose funds
- Addresses used the bech32 (BIP-173) checksum instead of bech32m (BIP-350), so
  every BIP-350 wallet rejected them. A vendored BIP-350 reference
  implementation is now used and the official BIP-350 vectors are tested.
- `migrate` generated a random key per destination and discarded it.
  Destinations are now derived from a BIP-39 seed and can be re-derived.
- `--mnemonic` and `generate_key_from_entropy` ignored their input and returned
  random keys. Keys are now derived deterministically (FIPS 204 seeded keygen).
- The CLI produced mainnet `bc1r` addresses, which are anyone-can-spend before
  activation. Testnet is now the default and mainnet needs `--allow-mainnet`.
- Taproot addresses were rated "low" risk. Their output key is on-chain, so
  they are now "high".

### Specification (BIP draft)
- New: the commitment is `TaggedHash("PQKeyCommit", key_type || pubkey)`, with
  a key type byte for future schemes and an upgrade hook for unknown types.
- New: a BIP-341-style signature message (tag `"PQSighash"`) replaces BIP-143,
  which was claimed in the docs but never implemented.
- New: FIPS 204 context strings separate transaction and message signatures.
- Fixed: scriptPubKey is `OP_3 OP_PUSHBYTES_32` (`5320...`), not `0x03 ...`.
- Fixed: witness order is `<signature> <key_blob>` everywhere.
- New: spending rules, annex handling, relay policy, sizes, wallet guidance,
  rationale and alternatives (P2MR, hybrid, ML-DSA-44, SLH-DSA, FN-DSA).
- Motivation now explains why migration must happen before a CRQC exists, and
  that witness v3 stays safe after the key is revealed (unlike P2WPKH).
- Test vectors: `docs/bip/0001-test-vectors.json`.
- Spending rules follow BIP-341's pattern: the key blob is always the last
  witness element and the stack shape is checked per key type, so future key
  types may use other witness layouts without a hard fork. Key type 0x50 is
  rejected explicitly, even when an annex is present.
- P2SH-wrapped witness v3 programs are explicitly left unencumbered and
  non-standard.
- Fixed the Delving Bitcoin discussion link.

### Other changes
- PSBT: real BIP-174 encoding. PQ fields use proprietary type `0xFC`; the
  previous proposal (0x07/0x08) collided with existing input types. Signing
  computes the sighash instead of accepting an arbitrary message.
- Fee and size estimates now apply the witness discount (1-in/2-out: ~1,455 vB,
  not ~5,384).
- Canary: the default is now a Taproot output keyed to the BIP-341 NUMS point
  (nobody holds its key), with Esplora polling.
- Key files store the 32-byte seed (not the 4,032-byte expanded key), are
  created with mode 0600 and are never overwritten silently.
- `generate-key` without `-o` no longer crashes.
- Removed the mock SNARK aggregation module: it could be forged, and
  pairing-based SNARKs are not post-quantum. See `docs/research/`.
- Dependencies: `pqcrypto` and `bech32` replaced by `cryptography` (OpenSSL
  ML-DSA) and `mnemonic`. Tests cross-check against `dilithium-py`.
- The library refuses to build outputs for undefined key types (those would
  be anyone-can-spend under the upgrade hook).
- Transaction and PSBT parsers reject non-canonical CompactSize, superfluous
  witness records, keydata on fixed-type PSBT keys, PSBT v2 and duplicate keys,
  and raise only ValueError on malformed input.
- Key files are written through a 0600 temp file and renamed into place, so
  the seed is never readable through old permissions or a symlink.
- Derivation paths must be ASCII decimal (no Unicode digits or underscores).
- `--spent-from` matches bech32 addresses case-insensitively.
- `--ask-passphrase` prompts for the BIP-39 passphrase; `--passphrase` warns.
- RPC URLs: percent-encoded credentials and IPv6 hosts work.
- CI on GitHub Actions.
