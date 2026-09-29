# Privacy contract: metadata-only-v1

HARSieve is a lossy diagnostic projection, not a secret detector. Its goal is to
remove free-form capture content without relying on a list of sensitive names.

## Transformation

The sanitizer constructs a new object. It never copies entire request, response,
entry or log dictionaries. Unknown keys are dropped at every supported level.

All request/response headers and cookies become empty arrays. Request postData,
response content text and encoding, redirect targets, cache content, pages,
comments, IP addresses and browser-specific extensions are omitted. A body is
removed regardless of whether it is text, base64, multipart or an unfamiliar
format; HARSieve does not decode it first.

Every origin is assigned a sequential alias in first-seen order. Origin grouping
uses scheme, case-normalized hostname and effective port. Credentials are not
part of the grouping. The entire raw URL path is separately aliased per origin;
query and fragment are removed. HTTP(S) and WS(S) schemes remain. Mappings stay
in process memory and are not exported. No raw-value digest is written.

The earliest request starts at 2000-01-01 UTC in the output; all other starts
preserve their relative offsets, rounded to milliseconds. Input order stays the
same, including unsorted captures. The maximum accepted capture span and each
duration are one year.

Methods are converted to a closed standard-method list or OTHER. HTTP protocol
strings and MIME types are also restricted to closed lists. Unknown protocol
strings normalize to HTTP/1.1; unknown MIME types become application/octet-stream.
These fallbacks intentionally lose detail and are not observations of the source.

## What remains observable

Request counts, order, endpoint equality, schemes, method categories, HTTP status,
timing phases, durations and byte sizes remain. These can fingerprint behavior
or disclose that an action happened. Standard strings that coincide with a secret
(e.g. a password literally equal to GET) are not globally scrubbed.

Do not call the result anonymous or suitable for all public disclosures. Review
the bundle against the recipient and your data-sharing policy.

## Limits

- No independent security audit or general guarantee of secret absence.
- HAR 1.2 only. This is a projection with targeted validation, not a complete
  HAR schema validator. Unsupported URL schemes fail the entire operation.
- 64 MiB raw file, 100,000 entries, 64 JSON nesting levels. The program holds the
  input and derived artifacts in memory; memory use can exceed raw file size.
- Unknown numeric sizes remain -1. Original size fields describe traffic, not
  the length of the removed bodies or rewritten headers.
- Original timing fields are retained, including browser-specific -1
  unavailability values. Recorded totals are not recomputed or asserted to equal
  timing sums. SSL is already part of connect and must not be added twice.
- Nonstandard fields, pages, original URLs and payloads cannot be recovered.
- Raw input remains on disk and in Python memory during processing. No guaranteed
  memory erasure, encrypted storage, deletion or subprocess sandbox is provided.
- Output directories use mode 0700 where POSIX permissions apply. Windows access
  control follows the parent directory and operating-system defaults.
- A crash or power failure during writing can leave a partial destination.
  Existing destinations are never reused. Use a directory controlled by you;
  protection against a local attacker changing paths concurrently is not claimed.
- Error messages for capture content omit raw values. Command-line usage errors
  may quote arguments supplied by the user; do not put secrets in arguments.
- HTML can be slow for huge captures; all request rows are rendered.
- Endpoint aliases are local to each run and must not be compared across captures.

## Audit semantics

Audit counts describe recognized arrays and body fields in the input:
header/cookie/queryString array lengths, presence of request postData and response
content.text. A URL query not repeated in queryString is still removed but is
not included in that counter. Unknown extension removal is policy, not an exact
count of all dropped properties.
