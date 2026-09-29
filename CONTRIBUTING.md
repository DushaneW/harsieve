# Contributing

Start with a focused issue or pull request. Use only synthetic captures in public
reports. Never attach real authentication headers, cookies or customer payloads.

Install requirements-dev.txt, then run unittest, Ruff checks and Ruff formatting
as shown in README.md. New behavior must include a regression case; privacy
changes also require a docs/privacy.md update.

Keep the core transformation pure and return new objects. Do not forward unknown
fields, add raw data to diagnostics or introduce network calls. Any addition to
retained metadata needs explicit review.

Prefer small, cohesive changes over framework migrations. Package dependencies
used for development are separate from the zero-dependency runtime contract.
Describe the problem, resulting behavior and commands actually run in your PR.
