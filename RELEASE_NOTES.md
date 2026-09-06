# Experimental community preview

ControlSpec provides portable typed controls, deterministic reference decisions,
binding rechecks and receipt assessment. This preview includes runnable personal
spending and sales examples, an optional enterprise compatibility profile, JSON
schemas and a Python reference client.

The public snapshot preserves the evaluator and reference catalog. Package
initializers isolate it from the older operational application, and the locked
dependencies include the test HTTP client and local server. No database is needed.

This is a community preview for experimentation and feedback. It does not grant
production permission, execute target operations, install custom published policy,
authenticate tenants or persist receipts. Review and tests are engineering evidence,
not independent assurance certification. No production deployment is included.

The public test suite covers the exported runtime and client. Internal workflow,
historical Git-provenance and legacy-documentation tests are retained in the
development workspace rather than shipped as public tests. Public package checks
verify copied source hashes and absence of operational database imports.

See [README](README.md) to run the examples and [CONTRIBUTING](CONTRIBUTING.md) to
report integration friction or propose a change.
