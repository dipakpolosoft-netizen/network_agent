# Step 16: Finding review

Open **Assets**, select a device, and expand **Evidence & vulnerability triage**.
The feed keeps five kinds of records separate:

- **Host scan:** rule-based exposure signals from a saved device scan.
- **NVD:** potential CVE matches to observed service CPEs, not verified
  vulnerabilities. The affected IP and observed port/protocol are shown.
- **Web check:** completed Nuclei baseline configuration observations.
- **Greenbone:** completed scanner findings. The bounded summary links back to
  its source scan; the full raw report remains in Greenbone.
- **SSH inventory:** hostname, OS, kernel, and package-count facts. These are
  not findings or patch-status assertions.

Each finding shows its source, observation time, asset target, source scan or
worker job, and whether it is linked to the latest saved scan. Historical
results remain available through **Show historical**. A newer completed worker
run for the same source and target makes older observations historical. Queued,
running, failed, and cancelled worker runs appear in **Worker run status**;
they never supply findings or prove that the target is clear. A completed run
with no finding only describes that run's checked scope, not the whole asset.
The feed is bounded; use source histories for omitted results.

Operators and admins can expand **Review** on an item and save one of:
Not reviewed, Investigating, Confirmed by reviewer, False positive, or Risk
accepted. False positive and Risk accepted require a reason. The decision and
note are stored separately from immutable scan/worker evidence in
`asset-evidence-reviews` (PostgreSQL documents in production, JSON in local
mode). Each change writes an Activity event with the actor, source, previous
status, and new status. Viewers can read reviews but cannot change them.
Decisions apply to the exact observation, not automatically to a later scan.
Refreshing NVD correlation on the same scan also requires a new review, even
when the CPE and CVE IDs are unchanged. The earlier decision remains in the
Activity trail but is not applied to the new assessment snapshot.

## Acceptance check

On one approved test asset, compare a saved host scan, an NVD lookup, and any
available completed central-worker jobs with their source reports. Confirm
the affected service, source ID, time, and classification for each item. Save
and reload a review decision, then verify a viewer cannot alter it and the
Activity event identifies the change. Run a newer completed check for the same
target and confirm older findings become historical. Exercise queued, failed,
and cancelled jobs: each must remain a run state, never a clean result. Keep
SSH packages as inventory facts. Record the test asset and job IDs, timestamps,
operator, approval reference, and screenshots before marking Step 16 field
accepted. This check does not start a network scan by itself.
