# LLDP topology

The **Assets > Topology** view is a site-scoped map of links reported by the IEEE LLDP remote-systems MIB. It is not a drawing of every IP on a subnet and does not infer a cable from ARP, ping, a shared gateway, or a route. The probe reads LLDP only from discovered hosts that respond to its existing SNMP identity request. It records the local chassis identifier, local port identifier, remote chassis identifier/subtype, remote port identifier, and remote system name. The relevant objects and remote-table index are defined in the [IEEE LLDP-MIB](https://www.ieee802.org/1/files/public/MIBs/LLDP-MIB-200505060000Z.mib).

The probe sends bounded SNMPv2c read requests to the already discovered IP. `FORGESEC_SNMP_COMMUNITIES` currently defaults to `public`; for a real deployment configure an approved, read-only community and restrict device SNMP access to the probe IP. `FORGESEC_LLDP_NEIGHBOR_LIMIT` defaults to 32 rows per table and is capped at 64. SNMPv3, CDP, bridge forwarding tables, and routed-hop topology are **not** implemented in this step. These are real gaps for sites that disallow SNMPv2c or whose devices do not expose the standard LLDP MIB.

The API saves the LLDP snapshot inside the durable asset observation, including the discovery ID and timestamp. A neighboring asset is resolved only when its recent site-local chassis ID/subtype is unique, or a MAC-form chassis ID exactly matches one unique recently seen site-local asset MAC. An ambiguous chassis ID is never resolved by a fallback MAC match. Duplicate, stale, or missing identities remain separate **LLDP-only neighbors** with no invented IP address. Legacy all-zero or multicast MACs cannot resolve a neighbor through the MAC fallback. The inspector shows the matching method and source discovery. Required LLDP table columns must finish their bounded walks and agree on row indexes before a new snapshot is accepted; a timeout, row-limit truncation, or mismatched table leaves the previous snapshot intact. A successful empty snapshot removes earlier links. Links older than seven days are hidden by default and can be inspected with **Show stale**. The graph response is capped at the 1,000 most recent link observations and reports truncation.

Each unresolved report gets its own LLDP-only node for the reporting asset and
local port. Matching chassis text from two sources is not enough to join them
into one physical device. The toolbar separates visible reported connections
from individual LLDP reports; reciprocal reports can describe opposite ends
of the same connection. If a report appears to name the reporting asset as its
own neighbor, it remains an unresolved LLDP-only report rather than being
discarded or drawn as a confirmed self-link.

## Field check

1. On a written-approved pilot site, enable read-only SNMP and LLDP on two managed devices. Confirm the probe can reach UDP/161 on those exact discovered IPs and that the device's LLDP neighbor table is populated. Do not enable SNMP merely to make an empty map look complete.
2. Record the device-side ground truth before discovery: management IP, system name, chassis ID/subtype, local port, remote chassis ID and port, interface count, and observation time for each of the two managed devices. Mask the community string in all captured evidence.
3. Run an approved discovery from that site's probe. In **Assets > Device depth**, compare the SNMP system name, object ID, uptime, and sampled interface names/statuses with the device management UI or read-only CLI. Uptime is a point-in-time value; interface sampling can be capped and is not a full inventory.
4. In **Assets > Topology**, compare each source and target, local/remote port, matching method, discovery ID, and observation time with the device-side LLDP neighbor table. An unscanned LLDP neighbor may remain unresolved; a server with no LLDP advertisement will not have a physical link drawn. A shared subnet or gateway must not create a physical link.
5. Repeat after a known, authorized topology change and confirm the new successful snapshot replaces the old link. A successful empty table should remove the link; a failed or truncated LLDP read should retain the prior snapshot as aging evidence, not claim a new empty topology. Check **Show stale** after the seven-day threshold.
6. Test a second site with the same chassis text and verify it never resolves across site boundaries. Check desktop/mobile pan, zoom, node selection, asset opening, empty state, and **Show stale**. Record mismatches, device firmware quirks, and any unsupported MIBs.

Record the approval reference, site and probe IDs, discovery IDs, device-side screenshots or sanitized command output, expected-versus-observed links, and a pass/fail result for each check. Step 11 is field-accepted only after the real-device comparison passes; automated fixtures alone do not establish topology accuracy on a customer network.

Automated tests cover parsing, bounded table completion, site-local matching, ambiguous and stale identities, and snapshot replacement. No live network device was contacted during this Step 11 work, so production topology accuracy remains **not field-validated** until this check is recorded.
