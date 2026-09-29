# Product rationale and launch plan

Research date: 2026-09-28. This is a product hypothesis, not a forecast of stars.

## Why this problem

The initial alternative was a dotenv validator. Existing tools already cover
linting, missing keys, schemas and CI checks, so a new general-purpose variant
would need a much more specific audience or workflow.

HAR captures have a concrete support/debugging use case and an explicit private-
data risk. Chrome documents sanitized exports that remove sensitive headers.
Cloudflare also provides a HAR sanitizer. This validates the workflow, not demand
for this exact implementation.

HARSieve's proposed position is a strict metadata-only projection plus a shareable
offline report. Its tradeoff is intentionally different from selective retention:
it gives up original hosts, paths, headers and bodies to preserve network shape.
It does not claim to be the first sanitizer, safer in every situation, or faster
than alternatives. No market-size or current star-count claims were used.

Sources:
- https://github.com/dotenv-linter/dotenv-linter
- https://github.com/fastify/env-schema
- https://developer.chrome.com/docs/devtools/network/reference
- https://blog.cloudflare.com/introducing-har-sanitizer-secure-har-sharing/
- https://github.com/cloudflare/har-sanitizer
- https://github.com/ahmadnassri/har-spec/blob/master/versions/1.2.md

## Audience

Frontend developers, QA engineers and support teams who need to explain slow or
failing browser requests without sending the original capture.

## First launch

1. Publish as DushaneW/harsieve with the README image and synthetic demo.
2. Run hosted CI and inspect the supported Python/OS matrix.
3. Create a release only after reviewing its artifacts. Attach the wheel and
   source archive, plus checksums. Do not claim a PyPI package exists.
4. Record a 20–30 second demo: run demo, open report, filter errors, sort slowest.
5. Write one useful post about what HAR captures contain, what HARSieve removes,
   and its limits. Link a synthetic example, not a real capture.
6. Share only in communities where self-promotion is allowed. Ask for concrete
   compatibility feedback, not reciprocal stars.
7. Address the first reproducible issues promptly and publish short changelogs.

## Suggested repository metadata

Description:
Offline HAR sanitizer with endpoint pseudonyms, a standalone waterfall report,
and zero runtime dependencies.

Topics:
har, devtools, privacy, debugging, python, cli, network, developer-tools

## Four-week validation

- Week 1: ask a few consenting frontend/QA developers to try the synthetic demo.
  Find installation friction and unclear output, rather than asking for stars.
- Week 2: improve compatibility using synthetic reproductions of actual issues.
- Week 3: publish a focused tutorial showing a latency incident from fake data.
- Week 4: decide the next feature from repeated feedback. Large report performance
  is a likely constraint, but measure it before adding architecture.

Useful signals: successful first run, repeat use, reproducible issues, outside
contributions and unsolicited sharing. Stars are secondary. 100 stars cannot be
guaranteed by a codebase or launch checklist.
