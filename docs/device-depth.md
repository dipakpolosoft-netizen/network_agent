# Step 23: Evidence-backed device depth

`GET /api/assets/{asset_id}/device-profile` presents two site-scoped snapshots:
the latest discovery observation and the most recent discovery with technical
SNMP system data. The profile is read-only and makes **no network request**.
For discoveries uploaded after this step, the asset observation keeps the
discovery method, latency, role confidence, and a maximum of 64 SNMP interface
rows. For older observations, the API recovers these fields from the exact
saved discovery ID, agent ID, device ID, and IP. It never attaches an SNMP
record by IP alone.

The asset drawer's **Device depth** expansion shows the discovery source/time,
role *estimate* and confidence, SNMP system name/description/object ID, uptime
at observation, and reported-versus-sampled interface counts. Admin/oper state
and speed are snapshots, not live telemetry. A prior SNMP snapshot stays
available after a later discovery without SNMP, but is labeled **Older
discovery**. Unknown values remain unknown. A 64-row cap is reported rather
than implying the interface table is complete.

SNMP contact and location are not copied into this asset profile. They remain
in the already saved raw discovery record, subject to its existing access and
retention policy. This step adds no new credential handling, SNMPv3 support,
WinRM collection, topology inference, package-to-CVE matching, or active
probing. SNMPv2c access and LLDP still require the approvals and field checks
in [topology.md](topology.md). The device profile is not a live device-health
monitor; a clean-machine pilot should compare values with the device's own
management UI before treating them as accurate inventory.
