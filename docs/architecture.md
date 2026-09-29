# Architecture

The pipeline has one important boundary: the original HAR never reaches the
report renderer or output serializer.

1. io.load reads a bounded byte sequence and rejects malformed UTF-8,
   duplicate JSON keys, non-finite constants and excessive nesting.
2. core.sanitize validates supported structure and builds a fresh HAR from
   selected metadata. Aliases are deterministic within each invocation.
3. report.summary calculates aggregate diagnostics. report.render embeds
   static CSS/JS and sanitized rows into a standalone document.
4. io.write_bundle exclusively creates a new directory and writes the three
   artifacts. Rendering completes before the directory is created.
5. cli.main handles commands and stable exit codes; capture errors do not echo
   source values or paths.

The standard library handles JSON, URL parsing, timestamps and argument parsing.
There are no runtime dependency packages or network clients. The urllib import
is urllib.parse only; it does not make requests.

Tests verify both public transformations and end-to-end CLI behavior. Fixtures
are synthetic and deliberately contain recognizable private-data canaries.
Aliases are sequential, not secret-value hashes.

The report uses escaped text, closed-vocabulary labels and numeric chart values.
It never interpolates an original URL, header or body. Its content-security policy
disables connections and external resource loading; static embedded scripts and
styles enable offline filtering. It does not turn CSP into an anonymity claim.

The chosen tradeoff is strict metadata projection over configurable redaction.
Adding a future retained field requires a review of the privacy contract and a
regression test. Feature requests to preserve content change the security boundary.
