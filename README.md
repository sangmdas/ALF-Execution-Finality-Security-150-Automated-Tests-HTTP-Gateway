# ALF Execution-Finality Security

### 150 Automated Tests + HTTP Finality Gateway

**Python reference model for Algorithmic Logic Fingerprint (ALF) accountability, output-specific validation, and fail-closed recommendation delivery.**

> **Computation is not authority to act.**

[![License: Non-Commercial Research](https://img.shields.io/badge/license-Non--Commercial%20Research-orange.svg)](LICENSE)

**Full technical disclosure:** https://zenodo.org/records/23659488

## What this repository demonstrates

This laboratory reference model illustrates three ALF relationships:

- **ALF-I:** identity of the approved algorithm/model configuration.
- **ALF-E:** recorded execution configuration and activation-generation state.
- **ALF-O:** commitment linking the validation evidence to an identified pending recommendation/output operation.

A protected *modelled* validator assesses an approved reference and creates an authenticated validation receipt. Separately scoped, non-bearer finality enablement is checked at a localhost HTTP delivery gateway acting as the **Finality Sink**. A valid request is delivered; an invalid or changed operation is withheld.

The reference implementation is a **Python laboratory simulation**, not a production trusted-execution environment or a verified implementation of all mechanisms in the full technical specification.

## Quick start

Requires **Python 3.10 or newer**.

```bash
python -m pip install -e '.[test]'
python -m pytest -q
python -m examples.http_demo
```

The HTTP demonstration runs on `127.0.0.1` using an ephemeral port and shuts down automatically.

## Laboratory outcomes

| Scenario | Expected gateway behavior |
| --- | --- |
| Approved model and intact output | `200 OK` — recommendation delivered |
| Model or feature configuration not approved | `403 Forbidden` — recommendation withheld |
| Model-generation change after validation | `403 Forbidden` — recommendation withheld |
| Changed content, recipient, or operation identity | `403 Forbidden` — recommendation withheld |
| Revoked, stale, invalid, or replayed authority | Withhold the covered operation |

### Exactly 150 automated pytest cases

| Test module | Test cases | Coverage |
| --- | ---: | --- |
| `tests/test_alf.py` | 13 | Baseline validation, tampering, expiry, revocation, sink binding, replay |
| `tests/test_expanded.py` | 125 | Parameterized descriptor, model generation, receipt, enablement, policy, concurrency, sink checks |
| `tests/test_http_gateway.py` | 12 | Local HTTP delivery and withholding integration tests |
| **Total** | **150** | **Functional laboratory assertions (including parameterized cases)** |

**Reproducibility:** run `python -m pytest -q` locally or open the repository's **Actions** tab. The workflow tests supported Python versions. `TEST_RESULTS.txt` contains the earlier recorded local run; subsequent test results should be verified independently.

## Reference execution flow

```text
Actual model/configuration activation
                 |
                 v
       ALF-I / ALF-E measurements
                 |
                 v
       Approved-reference validation
                 |
                 v
  Bind evidence to pending output (ALF-O)
                 |
          +------+------+
          |             |
          v             v
   Authenticated    Scoped non-bearer
   receipt          enablement
          |             |
          +------+------+
                 |
                 v
  HTTP Finality Sink reconstructs actual request
  and checks receipt, authority, epoch, generation,
  expiry, binding, and single-use state
                 |
         +-------+-------+
         |               |
       200 OK         403 WITHHELD
```

## Repository files

```text
alf_reference/core.py        ALF model, evidence, authority, Finality Sink
alf_reference/gateway.py     HTTP boundary and delivery decisions
examples/http_demo.py       Local end-to-end demonstration
tests/test_alf.py            Original 13 assertions
tests/test_expanded.py       125 additional parameterized cases
tests/test_http_gateway.py   12 integration tests
.github/workflows/tests.yml  CI validation
TEST_RESULTS.txt             Local execution record
LICENSE                      Non-commercial research license
pyproject.toml               Python package and test configuration
```

## Security boundaries and limitations

**Validated in this model:** selected output substitution, model/configuration mismatch, hot-swap/activation-generation changes, receipt/enablement tampering, stale policy, replay, one-process concurrent consumption, and HTTP gateway rejection.

**Not established by these tests:** actual protected observation of live model execution, hardware-backed attestation, independence from a compromised Python process, non-bypassability across all delivery paths, crash-safe distributed atomicity, correctness at a receiving display, or election fairness. Laboratory keys are intentionally **not secret** and must not be used in production.

150 test cases do **not** mean 150 unique attack classes were blocked. The HTTP demonstration confirms behavior only at its controlled localhost gateway boundary.

The direct-publication demonstration is separate from algorithmic recommendation and does not classify the lawfulness or acceptability of political expression. This repository does not accuse any platform or person of wrongdoing.

## Next engineering milestones

1. Instrument a live ranker and measure its actual activated model/configuration through a separately protected observer.
2. Separate the validator, authority controller, and delivery gateway into distinct trust domains.
3. Add crash-consistent protected consumption, revocation-race, and alternative-route tests.
4. Add cache/CDN and content-transformation profiles, along with actual latency measurements.
5. Publish reproducible threat-model results with precise assurance limitations.

## License — Non-commercial research use only

**Copyright © 2026 Sangam Kumar Das.**

The repository is **source-available**, but **not OSI-approved open source**. It is distributed under the **ALF Non-Commercial Research License 1.0**; see [LICENSE](LICENSE).

Permitted under the license: non-commercial personal/academic study, independent testing, research, and redistribution under the same non-commercial terms with attribution.

**Commercial use, integration, commercial evaluation, and deployment require a separate written agreement. No patent license is granted.** Patent rights and any separate licensing discussions are reserved. The code license applies to this reference repository, not automatically to the separate 481-page technical disclosure.

**Commercial/patent licensing inquiries:** info@sangamdas.com

**Research disclosure:** https://zenodo.org/records/23659488

> **Important:** This is a custom license, not a legal opinion or a substitute for professional intellectual-property review. If earlier copies of this code were distributed under Apache-2.0, changing the current release does not retroactively revoke rights validly granted to those earlier recipients.
