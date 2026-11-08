# PQ-HotStuff-2 message sizes and the transport limit

## Owner decision (2026-11-08): `MAX_MESSAGE_SIZE = 8,388,608` (8 MiB)
Recorded as `netmsg::MAX_MESSAGE_SIZE`. It is applied through `PqLimits::max_message_bytes`; `MessageLimits::derive` still checks it against the
chain's derived minimum. **Correction to the stated rationale:** at n = 1,000 a TC is 6,638,462 bytes (not ~4.4 MB) and a proposal that carries a QC
and a TC is about 9.96 MB even with an empty payload, so **8 MiB does not fit a 1,000-validator proposal**; `derive` returns `BelowMinimum` there
(asserted by `the_locked_8_mib_limit_covers_the_devnet_and_refuses_chains_that_need_more`). It does fit the four-node devnet (1 MiB payload) with
up to K = 7 sync blocks. A 1,000-validator network needs a larger limit or compact certificates (open decision D2); that is not decided here.
`netmsg::read_bounded` reads a stream in 8 KiB chunks with checked counting and stops the moment the cap is exceeded, never allocating from a
sender-reported length. Wiring it to the actual connection (and closing it on `TooLarge`) belongs to transport integration; libp2p's own fixed
16 MiB receive cap is unchanged.

## Original analysis (kept for the derivation)

## What the repository defines
* Genesis `limits.max_block_bytes` (devnet 1,048,576) and `limits.max_tx_bytes` (262,144).
* `chain-forge-p2p::NetworkConfig.max_message_bytes = max_tx_bytes x 2` (devnet 524,288). It is far below one 1 MiB payload plus its certificates, so it cannot be the PQ-HotStuff-2 limit. I found no caller of its check outside tests.
* The real libp2p gossip service has a fixed 16 MiB receive cap (`max_transmit_size`).
* **No PQ-HotStuff-2 message limit exists.** This work does not invent one: `MessageLimits::derive` fails with `LimitUnset { needed }` until the owner sets `PqLimits::max_message_bytes`, and with `BelowMinimum` if it is lower than the derived minimum. The transport path (and later the node driver) must call `derive` and refuse to start on an error.

## How the sizes are derived
Every size comes from the encodings of the draft layouts (spec 3.4 and the `CFH1|net|` envelope of `netmsg.rs`; the block wire layout is still open item U18). All arithmetic is checked `u64`; any overflow is an error. A test builds the largest possible message of every kind (all signers present, a TC with a nested QC, the full payload, the maximum number of sync blocks) and asserts that its encoded length EQUALS the derived limit, so the formulas cannot silently undercount.

For `n` validators, payload limit `P`, chain-id length `c`, `K` blocks per sync response (`H = 12` envelope bytes, a signature field is 3,313 bytes):

| Kind | Largest size |
|---|---|
| vote | `H + 4 + (4 + 104 + c) + 3313` |
| timeout (carries a QC) | `H + 4 + (4 + 43 + c + 3313) + (4 + QC(n))` |
| TC | `H + TC(n, n)` |
| proposal | `H + 56 + (4 + QC(n)) + (5 + TC(n, n)) + (4 + P) + 4 + 3313` |
| sync request | `H + 36` |
| sync response | `H + 36 + K x (4 + block)` |
| **minimum transport limit** | the largest of the above |

`QC(n) = 140 + ceil(n/8) + 3315 n`, `TC(n, n_h) = 72 + ceil(n/8) + 3323 n + QC(n_h)` (spec 3.4.3).

## Derived numbers (chain id of 24 bytes)
Minimum transport limit in bytes; the proposal and the sync response dominate (a vote is 3,461 bytes in every row):

| n | payload P | proposal | K = 1 | K = 4 | K = 8 |
|---|---|---|---|---|---|
| 4 | 64 KiB | 109,101 | 109,141 | 436,420 | 872,792 |
| 4 | 1 MiB | 1,092,141 | 1,092,181 | 4,368,580 | 8,737,112 |
| 31 | 64 KiB | 377,841 | 377,881 | 1,511,380 | 3,022,712 |
| 31 | 1 MiB | 1,360,881 | 1,360,921 | 5,443,540 | 10,887,032 |
| 100 | 1 MiB | 2,047,665 | 2,047,705 | 8,190,676 | 16,381,304 |
| 1024 | 1 MiB | 11,244,582 | 11,244,622 | 44,978,344 | 89,956,640 |

Timeout and TC messages: 16,805 / 26,778 bytes at n = 4; 106,313 / 206,010 at n = 31; 335,057 / 664,050 at n = 100; 3,398,232 / 6,797,792 at n = 1024.

## Findings and a concrete proposal (for the owner to accept, change or reject)
1. The existing p2p default (524,288) is unusable for PQ-HotStuff-2 at the devnet payload limit.
2. The fixed 16 MiB gossip receive cap bounds the choice. At n = 1024 even one proposal is 11.2 MB, so a sync response can carry only one block there; **a 1,000-validator network cannot use a signature-list QC within that cap for multi-block sync**, which is consistent with the open decision D2 (compact certificates or a committee).
3. **Proposal for the four-node devnet** (payload up to 1 MiB, `K = 4`): `max_message_bytes = 4,368,580` (the derived minimum), or `8,388,608` (8 MiB) which also allows `K = 7`. Both are far below the 16 MiB cap. A larger limit lets a peer make a node buffer and decode a larger message before rejecting it; the decoder checks the length against the kind's limit before parsing, but the transport still has to receive the bytes.
4. For any other `n`, payload limit or `K`, use `MessageLimits::minimum_transport_limit`, then choose a limit at or above it and at most the transport cap; `MessageLimits::max_sync_blocks_under` returns the largest `K` that fits a chosen limit.

Until the owner sets the value, the node must not enable this transport path. Storage, sync logic, recovery and the pacemaker do not depend on it and are exercised with the derived minimum for the test chain.
