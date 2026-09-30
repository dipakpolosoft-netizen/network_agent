# Long selected-host scans

The probe sends a busy heartbeat and a current progress snapshot every 20
seconds while a scan command is running. This continues while Nmap or a result
upload is blocked. A heartbeat failure is logged and retried without changing
the host's scan result. The API records when it last received progress; the
scanner shows elapsed time, the last update, counts, and running target IDs.
Progress is host-level: it does not claim a percentage of one Nmap host scan.
An intermittent progress-upload error is logged and retried by the next
snapshot; it does not change a host's scan result.

The probe checks the scan-control endpoint during host execution. Cancel ends
an active Nmap process, records cancelled targets, and retains already uploaded
results. Queued scans can be cancelled before the probe claims them. While a
claimed scan is stopping, the API keeps its status at `cancelling` even if an
older `running` progress update arrives. A second scan cannot be queued on the
same probe until the first has a terminal outcome. If a control check fails
while Nmap is active, the probe terminates that process rather than leaving
an unmonitored scan running.

Each profile has a per-host timeout in [scan-profiles.md](scan-profiles.md).
A timed-out host is recorded as `timed_out` with no invented port evidence.
The overall outcome is `completed` if all targets completed, `failed` if all
failed or timed out, `cancelled` if all were cancelled, and `partial` for mixed
outcomes. If the probe's final progress message is lost but its command ends,
the API derives a terminal outcome from saved host results; missing targets
are failed rather than silently counted as completed. Historical results stay
available in the scan report.

The probe retries a host-result upload up to three times for transport errors,
timeouts, rate limits, or temporary server errors, sending the same saved
payload each time. The API accepts an identical retry without duplicating the
result, including after the scan reaches a final outcome. It rejects a new
result after a final outcome, so a cancelled or completed scan cannot gain
late evidence. A permanent rejection is not retried. If delivery still fails, the
probe marks that target's delivery failed but retains its completed XML and
JSON locally for investigation; it does not replace that evidence with an
invented scan failure. A probe restart does not automatically replay that
local file. The API rejects progress that would downgrade a completed result
it already stored. Final progress cannot claim a completed host whose result
was never uploaded. The API reconciles a lost final command response from the
saved host results.

If a cancelled command loses its final progress message, saved completed
hosts remain completed: the scan becomes partial when other targets were
cancelled, or completed if every target had already finished.

## Verification

Offline tests use fake scanners and do not contact a target:

```powershell
Push-Location .\agent_builder
.\.venv\Scripts\python.exe -m pytest tests\test_scan_scheduler.py -q
Pop-Location
Push-Location .\services\api
.\.venv\Scripts\python.exe -m pytest tests\test_scan_flow.py tests\test_scan_reliability.py -q
Pop-Location
```

For a field check, first complete the approved pilot scope and use one known,
authorized target. Start a permitted long scan and confirm the probe remains
busy/online past its normal offline threshold, the running target and last
update change, and no second scan can start. Cancel one run and check that the
terminal result and any completed host evidence remain visible. Run a separate
approved timeout/partial-result case if available. A passing offline suite is
not proof that an installed service, firewall, or real Nmap job behaves this
way on a customer network.
