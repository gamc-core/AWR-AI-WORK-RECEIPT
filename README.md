# AI Work Receipt

When work is delegated to an AI, a person or another system, the final result
may not be enough to understand what happened.

AI Work Receipt defines a format and an offline verifier for examining the
evidence of that work: what changed, what was recorded, what was decided and
what remains unknown.

It checks the supplied evidence without requiring access to the original
working environment. It does not generate receipts, capture work automatically
or certify that the recorded events happened.

Experimental reference implementation, developed in September 2026.

[Run an example](#run-an-example) · [Interpret the result](#interpret-the-result) ·
[Limits and trust](#limits-and-trust) · [Examples](#examples) ·
[Technical reference](#technical-reference) · [Origin and license](#origin-and-license)

## Run an example

From this directory, using Python and its standard library:

```text
python verifier/verify.py examples/accepted/receipt.json
```

No package installation or internet connection is needed. Historically tested
on Windows 10 with Python 3.10.6; other platforms and Python versions have not
been tested.

## Interpret the result

The verifier checks receipt structure and canonical SHA-256, required objects'
hashes and sizes, available BEFORE/AFTER bytes, and references between work,
approval, validation and decision records. With comparable validation records,
it compares new, persisting and resolved failure sets. It does not rerun tests.

Recorded output excerpt from the accepted example:

```text
OBJECT_INTEGRITY       VERIFIED
CHANGE_RECORD          VERIFIED
APPROVAL_RECORD        CONSISTENT
VALIDATION_RECORD      CONSISTENT
FAILURE_COMPARISON     UNKNOWN
DISPOSITION_RECORD     CONSISTENT
```

Read each check separately; there is no overall "valid work" verdict.

| State | Meaning |
| --- | --- |
| `VERIFIED` | A named check was performed or recomputed. |
| `CONSISTENT` | Supplied records agree with their references. |
| `RECORDED` | An assertion is reported without authentication. |
| `UNKNOWN` | Not established by the package. |
| `PARTIAL` | Supporting information is incomplete; never partial approval. |
| `MISSING` | Required bytes or a named record are unavailable. |
| `MISMATCH` | A structure, digest or evidence contract disagrees. |
| `ACCESS_ERROR` / `TOOL_ERROR` | An access, tool or output operation could not complete. |

The full report shows recorded approval text, test outcomes, decisions and later
correction notes. A recorded `NO` or failing test outcome can still be
`CONSISTENT`. A missing BEFORE snapshot remains `UNKNOWN`, not proof of absence;
the [object states](spec/semantics.md#object-states) define the alternatives.

| Exit | Meaning |
| --- | --- |
| 0 | No required structural/integrity defect; documentary gaps can remain. |
| 1 | Required object bytes are missing. |
| 2 | Invalid structure, digest, evidence contract or command usage. |
| 3 | Access, tool or output error. |

See [results and command exits](spec/semantics.md#results-and-command-exits) for
precise conditions and error precedence.

## Limits and trust

AWR trusts the local Python runtime, verifier and specification. It checks
supplied bytes and references; historical events, actor roles, timestamps,
test outcomes and decisions remain supplied assertions.

It does not establish human identity, real authority, actual execution,
completeness of history, current workspace state, failure causality or quality
of work. An acceptance record is not authenticated approval.

Changes to supplied integrity-bearing content are detected unless the package is
consistently replaced and resealed. An independently held expected digest can
detect substitution of the receipt; one obtained only from the same package is
not an independent anchor. Neither authenticates the issuer or recorded events.

Use previously examined local packages. AWR is not a filesystem sandbox.
[Object-path checks](spec/semantics.md#object-states) explain links and concurrent
changes; [filesystem limits](spec/semantics.md#output-and-filesystem-boundary)
also explain why error reports may contain local paths and need review before
sharing.

## Examples

**[Accepted](examples/accepted/)** — a documented four-byte change with recorded
approval, validation and an acceptance decision. [Receipt](examples/accepted/receipt.json).
The human supplied the change text; an AI assistant transformed it into a
proposal, and the source system's native backend executed it. No AI executor
model is established. Historical tests concern the original candidate, not
the simplified example bytes. `AUTORIZO` means "I authorize"; matching those
bytes does not identify a unique event or person.

**[Honest failure](examples/honest-failure/)** — evidence of an accidental write
preserved without accepting it as valid work. [Receipt](examples/honest-failure/receipt.json).
It retains the exact byte `x`. BEFORE is `UNKNOWN`; AFTER is saved evidence,
not a claim of current file existence. Recorded checks concern saved evidence
and cleanup, not acceptance of the accidental write. A later note corrects the
sequence without rewriting the first record or accepting the accidental write.

Both are `DERIVED_EXAMPLE` packages with their own identities and hashes.
Their derivation records identify retained, summarized and omitted material;
they are not the original records.

## Technical reference

Format version: **0.1**. Verifier version: **0.1.0**. JSON output reports both.

```text
python verifier/verify.py examples/accepted/receipt.json --json
python verifier/verify.py examples/honest-failure/receipt.json --json
python verifier/verify.py --version
python verifier/verify.py examples/accepted/receipt.json --expected-digest <trusted-canonical-digest>
```

Replace the placeholder with the canonical receipt digest obtained through a
trusted channel or retained separately after review. JSON output calls it
`computed_digest`; it is not SHA-256 of the formatted JSON file.

- [Semantics](spec/semantics.md): the formal contract, including
  [comparison conditions](spec/semantics.md#changes-and-comparison-of-failures),
  [canonicalization](spec/semantics.md#receipt-canonicalization-awr-c14n-1) and
  [human/JSON output labels](spec/semantics.md#human-and-json-output).
- [Schema](spec/receipt.schema.json): admissible structure, read locally.
- [Verifier](verifier/verify.py) and [contract tests](tests/test_verify.py): implementation and checks.

Contract tests use disposable packages and local Python subprocesses:

```text
python -I -S -B -m unittest discover -s tests -v
```

## Origin and license

AWR is an independent extraction from work developed within Arquitectura
Simbiótica. [Project provenance](PROVENANCE.md) records its development,
contributors, historical reviews and the source of this snapshot.

Copyright 2026 Gonzalo Montero (GAMC). The code and specification are licensed
under the [Apache License 2.0](LICENSE).
