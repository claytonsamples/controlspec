---
title: ControlSpec — Before an agent acts
emoji: 🧭
colorFrom: green
colorTo: blue
sdk: static
app_file: index.html
pinned: false
license: apache-2.0
short_description: Exact-action approval and evidence, alongside OpenShell
---

# Before an agent acts

Explore nine recorded action-control experiments using the real ControlSpec
evaluator, TLS gRPC middleware targeting NVIDIA OpenShell v0.1.2, and a separate
synthetic HTTP target. Inspect approvals, changed requests, replay, missing proof,
outage and a real smolagents tool calling without a ticket.

**Static evidence replay.** Scripted requests and test-operator approvals; no
live LLM, money or external actions. The actual OpenShell sandbox runtime was
not run and is visibly marked unavailable. These are protocol/target tests,
not evidence of sandbox containment or a native-platform benchmark.

[Source and reproduction](https://github.com/claytonsamples/controlspec/tree/main/integrations/openshell) ·
[Experimental release](https://github.com/claytonsamples/controlspec/releases/tag/v0.1.2-preview.1) ·
[Report a failure](https://github.com/claytonsamples/controlspec/issues)

The prior six-scene action demo and seven original reference examples remain
available through links in the app. Raw observations are downloadable. No signup
or keys are required. ControlSpec is independent; no NVIDIA or Hugging Face
endorsement is implied.
