# MITRE ATT&CK Coverage Layer

[`soc-coverage-layer.json`](soc-coverage-layer.json) is a MITRE ATT&CK Navigator layer showing which techniques the SOC's 16 detection rules cover: **18 techniques and sub-techniques** in total.

| Colour | Meaning |
|---|---|
| Green (score 2) | Rule validated with an Atomic Red Team test (7) |
| Blue (score 1) | Covered by a rule, not yet validated (11) |

Hover over a technique in Navigator to see the rule numbers and validation evidence. Sub-techniques are expanded where a rule covers them, and parent techniques show the highest score of their sub-techniques.

## How to view it

1. Open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Choose **Open Existing Layer**, then **Upload from local**, and select `soc-coverage-layer.json`. If Navigator offers to upgrade the layer to the current ATT&CK version, accept.

A static image is in [evidence/attack-coverage-heatmap.png](../evidence/attack-coverage-heatmap.png). Validation details are in [evaluation/](../evaluation/README.md).
