# Security

ControlSpec is an experimental reference implementation. The current service has
no production authentication, tenant isolation, policy-publication authority,
target enforcement or durable evidence store. Run it on loopback for local
evaluation with synthetic inputs. Do not expose it as an authorization service
for real agents or give its examples production credentials.

A reference `allow` verdict is not permission to execute an external effect.
Caller-reported success is not verified execution. Hashes and binding checks
detect structural inconsistencies; they do not establish trust in an issuer.

## Reporting a vulnerability

Use [GitHub's private vulnerability reporting](https://github.com/claytonsamples/controlspec/security/advisories/new)
to contact maintainers before disclosing exploit details. Do not include a
vulnerability, exploit, credentials, private policy or personal data in a public
issue. If the private form is unavailable, open an issue containing only a
request for a private reporting channel.

A private report should identify the affected revision, expected security boundary,
reproduction steps using synthetic inputs, observed impact, and any proposed fix.
Please distinguish a violation of the documented reference boundary from a
production feature that this preview does not provide.

There is no published support window or response-time commitment yet. Security
fixes will be reviewed for the current preview; please include your exact revision
when reporting an issue.
