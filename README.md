# IETF agent-authorization evidence

Small, reproducible test cases shared in IETF mailing-list discussions. Each folder is
self-contained: what was run, the exact upstream commit it ran against, how to replay it, the
recorded results, and what it does not show.

| Folder | Discussion | What it shows |
|---|---|---|
| [`agentproto-evaluation-state/`](agentproto-evaluation-state/) | agentproto, `draft-konda-agentproto-evaluation-state` Section 7.1 | Test vectors for the draft's 15 test cases, checked against its freshness and evaluation-state rules, with the matching vectors in other drafts |
| [`aims-mba-revocation/`](aims-mba-revocation/) | WIMSE, multi-hop example for `draft-ietf-wimse-aims` | Component cases on the Mission-Bound Authorization reference code: a permit already issued versus a revocation applied afterwards, and two receivers holding different state |
| [`audit-record-freshness/`](audit-record-freshness/) | WIMSE, `draft-gilda-wimse-agent-audit-record` | An experimental signed companion that keeps a stale result, a never-obtained result and a forwarded copy distinguishable |
| [`dns-underscore-sizes/`](dns-underscore-sizes/) | dns-underscore-keys | Serialized DNS wire sizes for four underscore-label drafts |

These are discussion evidence. They are not conformance results, interoperability tests, measured
production behavior or proposed standard field names. Each README states its own limits.

Girish Konda
