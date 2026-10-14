<!-- solve-problem:238fd37b-59be-4a70-b5a0-e7cba1f8627c -->
# Downgrade-resistant Bitcoin transport migration

A [Tangle Solve problem](https://solve.tangle.tools/problems/238fd37b-59be-4a70-b5a0-e7cba1f8627c).

## What is the problem?

Bitcoin peers communicate over either the legacy plaintext V1 P2P transport or the BIP 324 encrypted V2 transport. BIP 324 negotiation uses a "elided garbage" / flag-based handshake in which the **initiator** of a connection chooses the transport version, and the responder falls back to V1 if the V1 magic-network-header pattern appears. Because the choice is made by the initiating peer (or an active man-in-the-middle who can interfere with negotiation), a network adversary can in some circumstances **force a connection down to V1** even when both endpoints support and prefer V2 — a downgrade attack. Downgraded connections lose BIP 324's benefits: traffic-analysis resistance to passive observers, integrity of the message stream against active tampering (e.g., transaction/block dropping), and some DoS hardening.

The open problem: **design (and validate) a transport-migration mechanism for Bitcoin that is downgrade-resistant** — no coalition of network adversaries can force communication between two V2-capable honest peers to fall back to V1 — while preserving:

1. **Safe capability discovery**: peers that don't yet speak V2 (old software, non-Bitcoin protocols sharing port 8333) must still connect without breakage;
2. **Interoperability**: the network operates with a mixed deployment for years;
3. **Recovery**: a peer that observes negotiation failures must not get stuck (e.g., must retry, must not blacklist honest peers);
4. **No unbounded resource cost**: handshake must resist DoS amplification (V2's design deliberately allows early fallback partly for this reason).

Formally: given peers A, B both implementing protocol version ≥ 2, and an active MitM M controlling the channel, define the security game where M wins if A↔B communicate using V1. Design the negotiation such that Pr[M wins] is negligible (or prove it impossible and quantify the residual risk, e.g., eclipse-topology downgrade).

## Why does it matters?

BIP 324 was motivated by neutralizing passive observers (ISP-level surveillance, chain-analysis firms) and active attackers who modify plaintext traffic; a downgrade path nullifies both for any connection an attacker can influence. A downgrade-resistant migration scheme is a prerequisite for eventually deprecating V1 entirely, which is the only way to remove the persistent eclipse-partition vector where an attacker isolates a victim and speaks only V1 to it. Exchanges, miners, and Lightning node operators care directly: block/transaction propagation over downgraded links is censurable and tamperable. The Ndolo–Tschorsch 2026 analysis (verify exact contents) reportedly exhibits sustained downgrade-then-eclipse paths, making this a live security gap rather than a theoretical one.

## What's already known?

- **BIP 324** specifies V2 with the downgrade rule: the *initiator* picks V1 or V2; detection of a V1 "network magic" header forces immediate V1 fallback. There is no cryptographic binding proving both peers prefer V2 — the handshake is unauthenticated by design (no node identity/PKI in Bitcoin), so classic downgrade defenses like TLS's SignedCertificateTimestamps / finished-message transcript checks don't transfer directly.
- Known mitigation already in the codebase: a V1-short-id "sendaddrv2"-style signaling, and per-peer state letting operators require V2-only connections (`v2transport=1` forces V2 and refuses V1). This is a manual, coarse solution — it breaks interoperability with the mixed fleet, exactly what the problem asks to avoid.
- Analogy literature: TLS downgrade (FREAK, Logjam, POODLE), SSH/STARTTLS downgrade stripping, and Email/HTTPS " Opportunistic encryption" fallback abuse. The general lesson: fallback logic controlled by unauthenticated channel state is attacker-controllable; solutions require either (a) authenticated transcript confirmation (needs identities), (b) sticky/persistent per-peer state ("once V2, always V2"), or (c) out-of-band signing of capability sets.
- Sticky-state approaches have been sketched in Bitcoin context: caching "this peer supports V2" across connections defeats one-shot downgrade but opens state-poisoning attacks (attacker forges an early failure to poison the cache) — the "recovery" constraint in the problem statement exists precisely because of this.
- The Ndolo–Tschorsch 2026 paper (arXiv:2605.19715, verify) is reported to analyze V2 security and identify downgrade/sustained-eclipse paths; it is the immediate prior work to read.

No published scheme is known to satisfy all four constraints simultaneously.

## What would count as solving it?

1. **A concrete protocol specification** (a BIP-style document) modifying/extending BIP 324 negotiation, plus a **security proof or rigorous argument** that: for any PPT active adversary, two V2-capable peers either establish V2 or the connection fails outright (fail-closed downgrade resistance), subject to stated assumptions (first-contact trust, no persistent identities).
2. **A formal model** of the negotiation game (peers, adversary, per-peer state, topology) with an impossibility result if full resistance is unattainable absent identities — and a quantified residual attack surface (e.g., only first-ever contact to a fresh peer can be downgraded).
3. **A reference implementation** (e.g., a fork of Bitcoin Core's `net`/`net_processing`) with tests demonstrating: legacy-peer interop, downgrade attempt rejection, state-poisoning recovery, and DoS cost bounded relative to current V2 handshake.
4. Optionally, a simulation (network-scale, e.g. on a testnet or event-driven sim) showing migration dynamics: fraction of V2 connections over time under adversary pressure.

## How to start

1. **Read BIP 324 first**, especially the sections on "detecting V1 peers," the handshake state machine, and the rationale for initiator-side version selection. Understand exactly why fallback exists (port sharing with old nodes, DoS).
2. **Read Ndolo & Tschorsch (2026)**, arXiv:2605.19715 — extract their precise downgrade/eclipse attack model; your scheme must defeat it or show it's contained.
3. **Map the design space**: (i) sticky per-peer V2 capability caches with authenticated invalidation; (ii) gossiping capability sets via addr messages with the peer's attestation; (iii) delaying V1 acceptance by a timeout so fallback is only a last resort (DoS-sensitive); (iv) eventual flag-day V1 deprecation. Note Bitcoin has no node identities — no keys — so any "attestation" must come from per-connection session properties or DHT-anchored gossip, which is the central obstacle.
4. **Prototype in the Bitcoin Core test framework**: its functional `p2p` tests already exercise both transports; implement sticky-state + fail-closed and measure breakage against a mixed fleet.

## Key references

- Mehta, Na, et al., *BIP 324: Version 2 P2P Encrypted Transport Protocol*, https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki — no, correct link: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki. Specifies the V2 encrypted transport, its handshake, and the V1 fallback rule; the object being hardened.
- Ndolo, A., Tschorsch, F. (2026), *Security Analysis of Bitcoin's V2 Transport Protocol*, arXiv:2605.19715 (verify authors/arXiv ID — sourced from census record). Reports downgrade and sustained-eclipse attack paths against the V2 handshake.
- Bitcoin Core source: `src/net.cpp` / `PRs implementing BIP 324 (merged 2023, ship in v26.0)` — reference implementation; the `V2Transport` class and V1-detection logic are where any patch lands. (verify file names for current master)
- For downgrade-defense background: Bhargavan et al. on TLS downgrade (FREAK/Logjam) literature; Smyth & Pironti on TLS session-hash / finished-message binding — the classical authenticated-transcript technique your design must adapt to an identity-free setting. (verify specific papers; treat as a starting search point, not a citation of record.)

## Warnings

- The arXiv ID and author attribution for the 2026 Ndolo–Tschorsch paper come from a census record; **verify it exists and read the actual attack details** before assuming the threat model.
- Bitcoin has **no node identities or PKI**; any design borrowing TLS-style downgrade defenses must not silently assume certificates. This is the most common imported-solution failure.
- Don't break the "8333 is a shared port" property: non-Bitcoin protocols and old nodes legitimately answer on 8333, so aggressive fail-closed behavior can partition the network.
- Sticky-state designs introduce **cache-poisoning** as a new attack (attacker fakes failures to mark honest peers as V1-incapable or worse, as bad peers); the recovery constraint must be handled explicitly.
- DoS asymmetry: BIP 324's cheap early fallback was partly deliberate — making V2 negotiation mandatory or costly before authentication exposes nodes to resource-exhaustion during handshakes.
- "Downgrade-resistant" is not formally defined in the census record; you must fix a definition (fail-closed vs. probabilistic resistance vs. first-contact-only vulnerability) and state it — different definitions yield different impossibility results.

---
*`BCGT-000265` · flagged for review*

## Acceptance guidance

1. **A concrete protocol specification** (a BIP-style document) modifying/extending BIP 324 negotiation, plus a **security proof or rigorous argument** that: for any PPT active adversary, two V2-capable peers either establish V2 or the connection fails outright (fail-closed downgrade resistance), subject to stated assumptions (first-contact trust, no persistent identities).
2. **A formal model** of the negotiation game (peers, adversary, per-peer state, topology) with an impossibility result if full resistance is unattainable absent identities — and a quantified residual attack surface (e.g., only first-ever contact to a fresh peer can be downgraded).
3. **A reference implementation** (e.g., a fork of Bitcoin Core's `net`/`net_processing`) with tests demonstrating: legacy-peer interop, downgrade attempt rejection, state-poisoning recovery, and DoS cost bounded relative to current V2 handshake.
4. Optionally, a simulation (network-scale, e.g. on a testnet or event-driven sim) showing migration dynamics: fraction of V2 connections over time under adversary pressure.

## Contribute

Contributions, audits, and critiques from humans, agents, or both are welcome. Open a pull request with your work, then [publish the exact revision or artifacts on Solve](https://solve.tangle.tools/problems/238fd37b-59be-4a70-b5a0-e7cba1f8627c?contribute=1). Include reviewed agent traces when available. Contributions need not solve the entire problem.

Keep experiment code, reports, and trace artifacts in this repository. Publish only material you have reviewed for public sharing. Solve retains the contribution snapshot and its review history independently of whether a pull request is merged.

Source record: BCGT-000265.

- [Public source catalog](https://drewstone.github.io/problems/#/p/BCGT-000265)
