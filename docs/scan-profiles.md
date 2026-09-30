# Selected-host scan profiles

All four profiles run Nmap on the enrolled Windows probe against **selected,
site-approved targets**. Discovery is a separate operation. The scan uses
`-Pn` (assume the target is up), `-T3`, service version probes, a per-host
timeout, and `--open`. Nmap may omit closed/filtered results from its output;
an unlisted port is not proof that it is closed. A timeout, firewall, or
nonresponsive service can leave the saved evidence incomplete.

| Profile | Requested ports | Version probes | Host timeout | OS fingerprint |
| --- | --- | --- | --- | --- |
| Inventory | Nmap's top 200 TCP ports | Light | 8 min | Only when probe is elevated and Nmap can do it |
| Network services | 8 fixed TCP + 10 fixed UDP ports below | Light | 12 min | Not requested |
| Standard | Nmap's top 1,000 TCP ports | Light | 15 min | Only when probe is elevated and Nmap can do it |
| Full TCP | TCP 1-65535; no UDP | Deeper | 45 min | Only when probe is elevated and Nmap can do it |

Network services requests TCP `22, 53, 80, 443, 445, 3389, 8080, 8443`
and UDP `53, 67, 69, 123, 137, 161, 500, 4500, 5353, 1900`. It needs an
elevated probe for UDP. UDP `open|filtered` is ambiguous, not confirmed open.
The top-port profiles use the probe's Nmap services-frequency data; they do
not mean the numerically first 200 or 1,000 ports.

Full TCP requires approval for that profile, exactly **one** selected target,
and a separate operator confirmation. The API enforces both constraints.
The probe's own host cannot be selected. Full TCP is not an all-UDP scan or a
guarantee that every service/version will be identified. Use it only for a
specific approved escalation, not as a bulk follow-up to discovery.

The device drawer's **Host check** Nmap commands are ad hoc diagnostics, not
the managed scan profiles above. They use shorter timeouts and save bounded
terminal output, not asset/port evidence or a scan report. Each Nmap Host
check still requires its matching site-approved profile at request time,
queue claim, and on the probe. Full TCP Host check also requires a separate
confirmation; ordinary Ping/DNS checks require an approved target but no scan
profile. Use the managed scan workflow when a report is needed.

New scan JSON records snapshot the **requested profile plan**. Scanner, the
report page, and PDF show its coverage and limitations; legacy reports with
no snapshot say that the command details were not saved. The plan is not a
packet trace or proof that all requested ports completed. Compare returned
per-host states and errors with the plan, and retain failures or partial work.
Current probes reject a scan command when its saved plan differs from the
probe's local profile definition. Rebuild and reinstall a probe after changing
profile coverage; older installed builds cannot enforce this check.

## Offline and field checks

Run the probe and API profile tests without contacting a target:

```powershell
.\agent_builder\.venv\Scripts\python.exe -m pytest agent_builder\tests\test_nmap_runner.py agent_builder\tests\test_scan_command.py -q
.\services\api\.venv\Scripts\python.exe -m pytest services\api\tests\test_scan_flow.py -q
```

For the field gate, follow the [approved discovery/scan pilot](discovery-scan-pilot.md).
See [long-scan reliability](long-scan-reliability.md) for progress, cancellation,
and timeout behavior.
On one known authorized host, compare an Inventory or Standard result with
the owner's known open port. Check the exact approved profile, returned port
states, report/JSON/PDF scope description, timing, and any error. Test Network
services or Full TCP only if separately approved. Do not broaden a real
network just to mark this gate complete.
