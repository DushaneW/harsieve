# CLI reference

## clean

~~~sh
harsieve clean INPUT.har -o NEW_DIRECTORY [--fail-on-http-errors]
~~~

Creates capture.har, audit.json and report.html. The parent directory must exist;
the destination must not exist, even if it is empty. Input is never modified.

With the optional gate, a successful write is followed by exit 1 if any recorded
HTTP status is 400–599. Status 0 is shown separately, not treated as an HTTP error.

## demo

~~~sh
harsieve demo -o NEW_DIRECTORY
~~~

Uses a built-in synthetic fixture. No real capture is needed. The demo intentionally
contains fake secrets, failures and repeated endpoints to exercise the projection.

## summary

~~~sh
harsieve summary INPUT.har
~~~

Prints JSON containing request count, HTTP errors, no-response count, nearest-rank
p95 duration, sum of known response body bytes and count of unknown body sizes.
Uses the same validation and projection pipeline; outputs no original strings.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Completed |
| 1 | Bundle written; requested HTTP-error gate failed |
| 2 | Usage, input, validation or output error |

## Run without installation

Replace harsieve with python -m harsieve from the source directory.

## CI usage

~~~sh
python -m harsieve clean test-results/network.har -o debug-bundle --fail-on-http-errors
~~~

Keep the input capture private. Review artifact-upload rules before attaching any
bundle; metadata still reveals traffic shape. The tool itself uploads nothing.
