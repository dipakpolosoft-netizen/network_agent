# Feature Step 19: Security boundary validation

This is the feature-closure security pass, separate from the older numbered clean-machine release pilot. Automated negative-path checks send requests only to in-process test apps and fake scanner processes. They do not scan a network.

## Boundaries enforced

| Boundary | Expected result |
| --- | --- |
| Wrong site | Probe discovery and scan uploads remain bound to the probe's current site. A worker can claim only jobs from its own site; a different worker cannot submit a result. |
| Excluded IP | An approved segment may contain exclusions. The probe passes those CIDRs to Nmap with `--exclude`, drops any unexpected excluded host before enrichment or upload, and the API rejects excluded discovery devices and scan results. A removed approval blocks late uploads and makes active control polls request cancellation. Discovery stops if it cannot verify control. |
| Unapproved profile | Selected-host scans and central jobs require the profile allowed by the site's current scope; the probe checks the signed command policy again before scanning. |
| Revoked probe or worker | Revocation invalidates the credential and records an activity event. Queued probe commands are cancelled; leased worker jobs are released. Historical evidence remains. |
| Expired identity | Enrollment tokens and operator sessions fail on expiry and create one expiry event. Expired worker leases cannot submit results. |
| Other customer | A production control plane is bound to one customer ID and dedicated store. Startup refuses a different customer ID against that store. Sessions from a separate customer store are not accepted. Sites are **not** customer tenants; every operator within one deployment can read its sites. |

Security-sensitive policy denials (HTTP 403, 409, 410, or 422) are appended as `security.request_denied` activity events with a route pattern, method, status, and known actor. They never include request bodies, query strings, cookies, or bearer credentials. Unknown/missing-credential HTTP 401 requests are rejected but are **not** written one-by-one to this activity stream, to avoid turning unauthenticated traffic into unbounded database writes; retain and monitor ingress/access logs for those attempts. Revocation and expiry have their own activity events. Audit storage must be included in backup and retention policy.

Operator API and probe/worker protocol responses, including early denials and credential-bearing enrollment or job responses, carry `Cache-Control: private, no-store`. This limits HTTP caching; it does not revoke copies already saved by a client or replace transport encryption.

## Local verification

Run `services/api/.venv/Scripts/python.exe -m pytest services/api/tests -q` from the repository root. The in-process suite checks role and CSRF denials, expiry, revocation, site/profile/exclusion enforcement, worker leases, and separate-customer stores without contacting a target network. A denied operator site or enrollment request must create no site or token. Denial audits use a matched route template, or a fixed route family when middleware rejects before routing; never a caller-supplied URL segment. Probe-side policy, discovery, and scheduling tests are in `agent_builder/tests/test_policy.py`, `test_discovery.py`, and `test_scan_scheduler.py`. These checks do not validate packet-level behavior or an installed Windows service.

At the 2026-09-29 local run, the API suite had **216 passed, 1 skipped**, and the three probe-side test modules had **37 passed**. The API tests include `no-store` on signed-out and CSRF-denied operator requests, probe enrollment, and authenticated/unauthenticated worker polling. This is a code/test gate only. The field gate below remains open, and the unsigned development installer is not a production release.

## Field gate

1. In a disposable lab with written permission, approve one test CIDR containing a deliberate excluded host. Capture traffic at the probe or switch: discovery must not send packets to the excluded IP, and the approved remainder must still be discovered. An API rejection alone does not prove no packet was sent.
2. Test one denied target/profile and wrong-site worker using test identities. Confirm no command reaches the probe or worker and inspect the corresponding activity event. Never use a real customer's address or secrets in a negative-path fixture.
3. Revoke a pilot probe and worker, then verify new authenticated polls/uploads are rejected. Exercise an expired enrollment token, operator session, and worker lease. Confirm no payload can be accepted after expiry.
4. From separate client machines, verify each customer's hostname, cookie, database, and runtime volume are isolated. A same-deployment site is only a job scope, not tenant isolation.
5. Confirm the installed probe is rebuilt from the code containing the exclusion fix. Automated tests do not update a previously installed Windows service. Record the build hash, test requests, packet-capture evidence, activity IDs, and approver before marking Step 19 field-accepted.

Cancellation is cooperative: a probe may send packets between control polls or while a network request is in flight. Revoke access, stop the local service if necessary, and verify traffic actually stopped in the pilot. A probe that cannot reach the control plane will cancel discovery; scan subprocesses also stop when control polling fails. Do not promise instantaneous remote kill.
