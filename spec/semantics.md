# AI Work Receipt v0.1 semantics

## Boundary

This format represents recorded evidence, not a certificate of truth.
`documented != authenticated`, `recorded != true`, `new failure != caused by
change`, `human act referenced != human identity verified`, and `preserved !=
current`. No signature, authority registry, chain or source-system runtime is
part of v0.1. Claims describe the represented work, which may be a derived example.

## Envelope and Claim<T>

Required fields: format, version, receipt_id, work_id, recorded_at, scope,
target_role, executor, executor_model, authorization, changes, validation,
disposition, evidence, limitations, relations, integrity. Additional fields are
rejected. Identities are local labels, not globally authenticated identities.
`recorded_at` is an ISO UTC timestamp ending in Z, recording this receipt,
not backdating it to the original event. ASCII digits are required; fractional
seconds, if supplied, have exactly three or six digits. Calendar validity is
checked locally. The timestamp is recorded, not trusted.

Each claim is exactly `{value, classification, evidence_reference}`. v0.1 uses
string or null values. Classification is VERIFIED, DECLARED, INFERRED or UNKNOWN.
UNKNOWN requires null, and a non-UNKNOWN claim requires a non-null value.
VERIFIED requires an evidence reference. References identify local evidence ids.
The issuer's classification is retained; it is not trusted as authentication.
The verifier checks named properties of supplied records and never upgrades an executor,
model or authority assertion to cryptographically authenticated identity.
`target_role` states whether the represented object is a candidate, applied work,
saved evidence or another explicitly described role. Derived bytes are not
silently treated as the original promoted, executed or validated bytes.

## Object states

Every descriptor has exactly state, sha256, size_bytes, evidence_reference.

| State | Digest / size | Meaning |
| --- | --- | --- |
| OBJECT | SHA-256 and nonnegative byte size | Exact bytes must be shipped and checked. |
| HASH_ONLY | SHA-256; size may be null | Digest recorded, bytes unavailable; no byte comparison. |
| ABSENT | Both null; evidence reference required | Absence observation documented, not an empty file. |
| UNKNOWN | Both null; reference may be null | Existence/absence is not established. |

If BEFORE was not captured, it is UNKNOWN, never automatically ABSENT. An ABSENT BEFORE
requires an OBSERVATION document for that work, target and phase. This verifies
the absence *record*, not the historical filesystem itself. HASH_ONLY does not
prove possession of bytes or that the digest's original assertion was true.
OBJECT filenames are exactly lowercase SHA-256 inside `objects/`, adjacent to
the receipt. No paths or remote locators are interpreted. For each object, the verifier
checks that the resolved path is within the resolved objects root before opening
it. An individual object link that resolves outside that root is rejected.
The objects root itself is not rejected merely because it is a symbolic link
or junction: its destination becomes the resolved reference root. There is no
atomic containment guarantee if files or links change between checking and
opening.

AWR is not a filesystem sandbox. Use previously examined local packages without
unexpected links. For packages of untrusted provenance, use appropriate
operating-system isolation; AWR does not provide it.

Object hashes cover unchanged raw bytes, including CRLF, LF and Unicode
encoding. Reading structured evidence happens only after its raw digest matches.

## Receipt canonicalization: AWR-C14N-1

- Parse strict UTF-8 without a BOM. Reject duplicate keys at every depth,
  invalid UTF-8, lone surrogates, NaN, infinity, fractions and exponent notation.
- Only JSON strings, booleans, null, arrays, objects and integers from
  -9007199254740991 through 9007199254740991 are admitted. Booleans are not integers.
  Parsed integer -0 is canonical integer 0. No floating point values in v0.1.
- Retain every field except `integrity.digest` itself. Keep the integrity
  algorithm and canonicalization identifier in the hashed body.
- Sort object keys by Unicode code-point order. Preserve array order.
- Encode UTF-8 with no BOM, no indentation, no spaces at separators, and no final
  newline. Use `,` and `:` as separators; lowercase true, false and null.
- Leave non-ASCII characters unescaped. Escape quote as `\"`, backslash as `\\`,
  and backspace/formfeed/newline/carriage-return/tab as `\b/\f/\n/\r/\t`.
  Other U+0000..U+001F characters use lowercase four-digit `\u00xx`.
  Forward slash is not escaped. Unicode is not normalized.
- SHA-256 of those bytes is the lowercase hexadecimal receipt digest.
  Formatting whitespace of the serialized receipt is not integrity-bearing;
  newlines *inside strings* are. External objects are never canonicalized.

A receipt's self-seal detects modifications that leave that seal unchanged. A
resealed, self-consistent replacement requires an independently held digest to
detect. The optional external digest checks equality with an independently held digest.
It does not authenticate the author or establish factual accuracy.

## Evidence documents

Evidence entries have id, kind, object, description. Ids are unique. A claim's
reference must resolve. Typed records below are checked only when consumed;
unknown/unavailable records do not become truth. JSON documents use the same
strict parsing domain as the receipt. They are hashed as raw bytes, not by JSON
canonicalization. Records have exactly the following fields:

- HUMAN_ACT: raw UTF-8 content. Its bytes must equal the referenced claim value.
- AUTHORIZATION_BINDING: work_id, scope, human_act_sha256, targets,
  representation. Targets are `{target, before_sha256, after_sha256}` in receipt
  change order. representation is DERIVED_EXAMPLE or DOCUMENTED_WORK. Scope and
  supplied human-act digest must agree. Missing literal act remains explicit;
  a derived binding documents a mapping, not authorization of the derived work.
- VALIDATION: work_id, scope, method, environment, subject_sha256, subject_role,
  phase, test_ids_run, failing_test_ids, outcome. Phase is BEFORE or AFTER.
  Subject_role is HISTORICAL_ORIGINAL or DOCUMENTED_WORK. For DOCUMENTED_WORK,
  subject_sha256 must match a change digest on its BEFORE/AFTER side. Test identities may
  be null if omitted/not captured; otherwise they are unique nonempty strings.
  Failures must be a subset of the recorded executed population. An outcome
  label is recorded, not a new execution or an inferred human acceptance.
- DISPOSITION: work_id, decision, scope, actor. Decision must match the disposition
  claim. Actor is a recorded name, never an authenticated authority assertion.
- OBSERVATION for BEFORE absence: work_id, target, phase='before', state='ABSENT'.
- CORRECTION: work_id, type='ADDITIVE_CORRECTION', prior_record_modified=false,
  sequence (strings), raw_secured_before_removal (bool),
  record_completed_before_removal (bool). A relation points to this record and
  the represented work. It records a later account without rewriting the first record or accepting
  the original work. The sequence and booleans remain DECLARED in the result.
- DERIVATION: supporting content describing how an example was made. Its raw
  hash is checked, but its content is not parsed or interpreted by v0.1.
  The examples use JSON for readability. The verifier does not retrieve the
  source system or authenticate the described history.

Human identity, legal/organizational authority and cryptographic authorship stay
UNKNOWN. A match of supplied human-act bytes does not change that. Executor/model
claims remain recorded assertions even when their evidence bytes match.

## Changes and comparison of failures

Change targets are unique labels; the verifier never reads that label as a
filesystem path. Available BEFORE/AFTER bytes produce an exact common-prefix /
common-suffix change interval, showing offset and changed lengths. Hex previews
are capped at 64 bytes per side with an explicit completeness flag. More complex
changes can share one interval; original bytes remain available for full review.
Unknown/HASH_ONLY/ABSENT sides cannot produce a complete byte comparison.

Validation is a record check; tests are not rerun. Historical validation does not
validate modified example bytes. Baseline and current references must be distinct
and have BEFORE/AFTER phases. Comparison requires the same work, scope, method,
environment and subject role, known failure/test identities, a nonempty baseline
population, and execution of every baseline test in AFTER. No baseline, unknown
identities or mismatched scope/environment means UNKNOWN. Code digests may differ:
that is precisely why BEFORE/AFTER are compared. The verifier computes:

`new = after - before`, `persisting = after & before`, `resolved = before - after`.

These sets compare recorded outcomes; they never assign causal responsibility.
Test records, acceptance, saved evidence, applied changes and current state
remain separate.

## Results and command exits

Ten named results: RECEIPT_STRUCTURE, RECEIPT_INTEGRITY, OBJECT_INTEGRITY,
CHANGE_EVIDENCE, AUTHORIZATION_DOCUMENTATION, EXECUTOR_CLAIM, VALIDATION_EVIDENCE,
FAILURE_COMPARISON, DISPOSITION, LIMITATIONS. Statuses used in v0.1:
VERIFIED, CONSISTENT, RECORDED, PARTIAL, MISSING, MISMATCH, UNKNOWN,
ACCESS_ERROR and TOOL_ERROR.
No universal “valid work” result.

VERIFIED means structure, hashes, byte comparisons or failure-set arithmetic
were checked or recomputed. CONSISTENT means supplied approval, validation or
decision records agree with their references. It does not mean the approval is
positive, the tests passed, or the decision is authenticated. RECORDED means
the executor assertion or limitations are reported without authentication.
PARTIAL means some supporting information is available, but the named check is
incomplete. MISSING means required bytes or a named record are not available.
MISMATCH means a contract or digest disagrees. UNKNOWN means not established.
Issuer claim classifications are separate from these verifier results.

Exit 0: no required structural/integrity defect, even if documentation is partial
or unknown. Exit 1: missing required OBJECT bytes. Exit 2: structure, digest,
size or consumed evidence-semantic mismatch. On receipt seal failure, downstream
checks remain UNKNOWN. Exit 3: receipt/schema access, object access or output failure. An access error
never establishes absence. Invalid command-line usage uses argparse exit 2.
A semantic evidence error marks RECEIPT_STRUCTURE MISMATCH;
checks completed earlier remain visible. Exit 2 is used unless an access/tool
failure already requires exit 3.

The bundled schema has a deliberately bounded, local validator for precisely
its own keyword subset. It is not a general JSON Schema engine. No URI is fetched.
The schema handles shape; this document and domain checks handle meaning.

## Approval text and human output

The approval check compares text bytes and a binding's work id, scope and target
digests. It does not decide whether the text approves anything. A record of NO
can be CONSISTENT; a FAILED test outcome can also be CONSISTENT. Human output
shows the text, test outcome, decision, limitations and any later correction.

SHA-256 of AUTORIZO identifies those eight UTF-8 bytes, not a unique event,
person, session, authority or contextual intent. A binding records an association
with the represented work. That association is not authenticated and can be
fabricated along with the rest of a self-consistent package.

## Human and JSON output

Human labels and JSON `checks` keys represent the same check and status:

| Human label | JSON key |
| --- | --- |
| APPROVAL_RECORD | AUTHORIZATION_DOCUMENTATION |
| CHANGE_RECORD | CHANGE_EVIDENCE |
| EXECUTOR | EXECUTOR_CLAIM |
| VALIDATION_RECORD | VALIDATION_EVIDENCE |
| DISPOSITION_RECORD | DISPOSITION |

All other check labels match their JSON keys. The shorter labels do not add an
approval decision or an authentication claim. PARTIAL in APPROVAL_RECORD means
incomplete documentation, never partial approval. The supplied authorization
scope is displayed with its claim classification; a missing approval text stays
explicit.

## Output and filesystem boundary

CLI stdout and stderr use UTF-8, including redirection and pipes. Human output
and JSON are separate presentations of the same checks. An output failure is a
tool failure, not evidence absence. A closed stdout pipe returns process exit 3;
the checker redirects the failed descriptor to the null device before shutdown
to prevent a second buffered flush from replacing it with exit 120.

Access and tool error details may include local filesystem paths. Review reports
before sharing them; do not publish them automatically.

On Windows, long paths are read using the extended-path form. No registry
settings are changed. A missing required OBJECT uses exit 1. Denied access or
a path error uses ACCESS_ERROR and exit 3; an unreadable receipt/schema uses
TOOL_ERROR and exit 3. When multiple defects coexist, a tool/access failure
takes precedence over evidence exit codes.

OBJECT_INTEGRITY checks supplied OBJECT descriptors. UNKNOWN, HASH_ONLY or ABSENT
change sides remain explicit in CHANGE_EVIDENCE; they do not invalidate hashes
of bytes that are supplied. Missing validation documentation can produce MISSING
with exit 0, unlike a missing required OBJECT. No tests are rerun.

An external expected digest accepts upper- or lowercase hex. It is the canonical
receipt digest, not SHA-256 of the indented receipt.json file. JSON output's
computed_digest is the recomputed canonical digest. Retain it separately, or
obtain an expected digest through another trusted channel, to use it as an
anchor. A digest supplied only by the package under examination cannot detect
a complete replacement of that package.

## Verifier identification

The CLI supports --version without a receipt path. JSON output includes
format_version and verifier_version, including results for invalid input.
Format 0.1 and verifier 0.1.0 are independent identifiers. No release or
publication is implied by these version fields.
