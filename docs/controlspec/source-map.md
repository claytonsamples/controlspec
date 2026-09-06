# Source identity

This public preview is a source snapshot of the ControlSpec reference core and
integration examples. The repository release commit identifies the public bundle.
[SOURCE_MANIFEST.json](../../SOURCE_MANIFEST.json) records SHA-256 values for the
copied source files. Older revision identifiers inside fixtures describe their
development origin; that private development history is not included here.

Three package initializers are intentionally inert so importing the reference
API does not import the operational enterprise application. The reference
evaluator, canonicalizer, catalog, API and client bytes are preserved. Packaging,
dependency declarations and public documentation are specific to this preview.

The optional enterprise profile retains compatibility contracts and deterministic
selection helpers. The supplier application, database, execution service and
assurance ledger are absent. No production deployment or independent assurance
certification is claimed. See the [README](../../README.md) for runnable examples.
