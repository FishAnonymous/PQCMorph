# Reconstructed fault catalog

The manuscript specifies ten semantic fault families, six cases per family, but not the original variant code or precise baseline malformed input. The sixty cases here are new **executable application-wrapper mutants**. They change key/ciphertext routing or TLS arguments before real OpenSSL calls. They do not modify libcrypto internals and do not simulate verdicts.

All cases run the same tests without short-circuiting. The oracles never receive the family or variant identifier. Each mutant is paired with an unmodified adapter using the same source key/ciphertext. Commands, actual outputs and adapter transformation traces are retained. KEM variant `v` uses algorithm `[512, 768, 1024][v % 3]`.

| Family | Variants 0–5 | Principal distinguishing observation |
|---|---|---|
| KEM-WRONG-KEY | 0–2 route all requests for the original key to an independent key; 3–5 do so only for the reference ciphertext | K1 loses equality |
| TLS-HYBRID-TYPO | Six explicit misspellings of the hybrid token in client groups | Nominal hybrid handshake fails |
| CT-ALIAS | 0–2 replace changed, same-length ciphertext with cached ciphertext; 3–5 restore both cached ciphertext and key | K2 returns the reference secret |
| WRONG-KEY-ALIAS | 0–2 replace an alternate key with the original key; 3–5 restore both key and ciphertext | K3 returns the reference secret |
| TRUNC-PAD | Restore suffix / zero-pad any short input; restore suffix for one / up to two missing bytes; zero-pad for one / up to two missing bytes | K6 accepts a repaired invalid-length input |
| SERIALIZE-BYPASS | 0–2 return a cached original key handle; 3–5 serialize the cached original key instead of the requested key | Core K4 survives; K4-REPLACE distinguishes |
| SILENT-FALLBACK | Six permutations of Hybrid/Classical/PQC groups replace a hybrid-required server list | Classical peer unexpectedly connects |
| DROP-PQ | Remove pure-PQ from Mixed; optionally replace it with X448, P-256, P-384, P-521 or X25519 | Pure-PQ peer loses compatibility |
| VERSION-FORCE | Replace requested TLS 1.2 with TLS 1.3, with six hybrid-retaining preference lists | Version-incompatible source unexpectedly succeeds |
| UNKNOWN-SUBSTITUTE | Replace unknown client token with six classical lists that include X25519 | Unknown configuration silently connects classically |

The exact token lists, predicates and scope are inspectable in `src/faults.py`. Some variants share a semantic defect while differing only in algorithm or preference list; sixty cases are not sixty statistically independent defect families.

## Suites

**Smoke:** one valid KEM round trip, one hybrid/hybrid handshake, and rejection of an **empty ciphertext** with no secret output. The paper does not specify its malformed-input bytes; empty input is this reconstruction's explicit choice. Two global truncation-repair variants also repair empty input, while the four short-tail variants do not. Thus 14/60 is an observed property of this particular reconstruction, not a recovered original baseline.

**Core:** K1–K6 plus nominal hybrid success, hybrid-required/classical rejection, Mixed/PQC success, version mismatch rejection and unknown-group rejection. Capability extension and bounded interruption are additionally covered in the unmodified full core workload; the mutation benchmark contains no dedicated hang/freshness mutant family, matching the ten-family scope.

**Extended:** core plus the empty-input check and **K4-REPLACE**. The empty-input check does not add any kills beyond core in this benchmark. K4-REPLACE serializes/reloads an independent replacement key and demands that decapsulation not reproduce the old secret.

## Why the serialization distinction matters

The paper's K4 predicate checks equality after saving and loading the **same key**. Both a real reload and a cached original key produce that equality. A pure bypass is therefore observationally equivalent under this predicate. Simply labeling the bypass “killed” would not establish that an executable oracle observed a difference.

The additional key-replacement transformation makes the two implementations distinguishable: a proper reload uses the replacement key, whereas a bypass keeps using the old key. We report core **54/60**, extended **60/60**, and smoke **14/60** separately. This reveals a limit of the stated predicate for these mutants; it does not prove that the lost original benchmark used the same bypass semantics or lacked other instrumentation.

## Statistics and limits

The report computes a two-sided exact McNemar/binomial test from paired outcomes. The test describes the selected cases, not general defect prevalence. Fault families were designed from the same semantics as the relations. Their adequacy score does not establish detection of historical OpenSSL vulnerabilities, unseen applications, or all PQC migration faults. No original fault source or observations were available to establish equivalence with the paper's mutation study.
