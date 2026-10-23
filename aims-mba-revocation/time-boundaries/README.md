# Exact temporal boundaries: W7 extension

This extension adds 21 cases without changing the eight existing W7 cases. Fixture scaffolding is adapted from Girish Konda's BSD-3-Clause test file. Mikhail Sergeev prepared the extension with AI assistance.

| MBA commit | Executed extension cases | Result |
|---|---|---|
| `ea1a1490716f045d9fda42d73b1a7b891dea5fb9` | All 21 | 21 passed, 0 failed, 0 skipped |
| `c941a738f11ea66ace2af4be5932477b21b4fce1` | B7 pair only | 2 passed, 0 failed; 19 not selected |

Both rows are actual local MBA component runs, repeated before preparing this contribution. They are not arithmetic reference-model results or distributed deployment tests. Passing B7 characterizes observed issuance behavior; it does not establish enforcement of S at final issuance.

- [Original-pin tests, expected results and replay](ea1a149/README.md): issuance at S-1 ms, S and S+1 ms; held-permit admission around expiry; combined original-as-of S+L; current-source versus cached-state revalidation; and delay across the issuance boundary.
- [Newer-pin B7 rerun](c941a738-b7/README.md): unchanged temporal assertions with the required Resource-policy fixture and receiver teardown adaptation. The other 19 cases were not rerun on this pin.

The injected clock has integer-millisecond resolution, epsilon 1 ms and zero configured skew/grace. S and L are each 300,000 ms. Real clock accuracy is unmeasured. Each attempt uses a fresh fixture.

The state-age gate accepts equality. Issuance additionally requires a deadline later than the issuance time. Permit use accepts equality with its deadline, subject to other validity checks. These are distinct stages.

B7 starts evaluation at state age 299,999 ms and advances the injected clock by 2 ms in an allowing FGA stub. With explicit future expiry supplied by the Girish-style adapter, the PDP issues at age 300,001 ms with a deadline 600,001 ms after the original as-of. The observation-only control returns `stale_state`. B7 contains no revocation and does not attempt use at the returned deadline.

The admission revalidation cases use test adapters around real PDP evaluation. They do not add a production admission guard to MBA. The successful effect is reading a local SQLite fixture invoice; no external payment is made.

For example wording, a proposed inclusive convention is:

> This example uses inclusive limits: state age may equal S, and an outstanding permit may be used at, but not after, its expiry, provided all other validity conditions hold. Issuance requires a permit deadline later than the issuance time.

S must be enforced at final permit issuance for the stated derivation. An admission-time recheck preserves the original as-of time when it uses cached state. Neither the proposal nor these runs establishes AIMS consensus, conformance, interoperability, deployed revocation latency or termination of already-admitted actions.
