# OpenShell recorded-evidence interface

`openshell-template.html` is a self-contained display of the version 1 report
contract from the integration harness. It does not authorize, evaluate, invoke
an agent, or send transactions. It needs no network request to replay evidence.

The build owner replaces the single `__OPENSHELL_DATA__` marker with report JSON
and publishes the complete report beside the generated page as
`openshell-traces.json`. Before embedding JSON inside a script element, escape
`<` as `\u003c` so source data cannot terminate the element. Display strings use
`textContent`; source data never becomes HTML.

The page links to `action-demo.html`, `reference-demo.html`, and the public
`integrations/openshell` source directory. Preserve these destinations when
publishing the Space.

## Display rules

- The only observed lane status is `observed`. Missing lanes, `not_run`, and
  unknown statuses display no asserted target state.
- Absent, negative, noninteger, or unsafe integer state values display
  `Not recorded`, never a fabricated zero.
- A `not_run` runtime is displayed independently of gRPC fixture verification.
  The combined lane is labeled as a protocol fixture until runtime status is
  `passed`; this is a display of supplied provenance, not an independent check.
- The four replay phases are presentation steps over one recorded scenario.
  Playback timing is not a latency measurement.
- A nonempty evidence object is called recorded evidence. The UI does not infer
  reconciliation or verified completion from its presence.
- Scripted test operator approval is explicitly described as simulated.
- Malformed report JSON or an unsupported schema stops the comparison display.

## Frontend verification

Tested in headless installed Microsoft Edge using bundled Playwright. The test
created an in-memory report explicitly labeled `UI TEST FIXTURE ONLY`; it did
not create published observations or leave a fixture in this repository.

Observed checks passed: initial rendering; three phase advances; unavailable
native lane displaying an em dash with no asserted zero; before/after state
rendering; reset; disabled final-step control; 390 px mobile layout without
horizontal overflow; missing state displaying `Not recorded`; malformed JSON
showing a load error; no browser page errors. Desktop 1440 px and mobile 390 px
screenshots were visually reviewed. JavaScript syntax was checked with Node's
`vm.Script`.

These checks validate the presentation only. The build owner must validate the
actual generated report, source revision, integration outcomes, and published
links before release.
