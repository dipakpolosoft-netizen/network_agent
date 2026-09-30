# Step 17: Operator workflow acceptance

The UI path is **site policy -> probe -> approved scope -> discovery -> targets
and profile -> scan progress -> asset evidence/topology -> history/report**.
This checklist does not authorize a network scan. Use only the pilot's written
approval and approved targets for any live discovery or scan.

## Local UI pass

1. Sign in as an admin, operator, and viewer. A viewer can read evidence but
   cannot approve networks, launch scans, or change review decisions.
2. Select a site with a probe, then a site without one. The active probe and
   discovered data must switch or clear; no old site's devices may appear as
   the new site's current results. Select a probe from another site to switch
   back. Open **Assets** and confirm it starts on the selected site.
3. On an approved site, confirm discovery launches from the selected scope's
   row and still requires the authorization dialog. A running discovery has
   one visible Stop action and its progress is clear.
4. Select targets in one approved network, then across networks with different
   profile permissions. Only profiles approved for every selected target may
   be chosen. With no common profile, Scan is disabled and explains why.
   A running scan cannot be launched again; progress and Cancel are visible.
5. Open a device and its durable asset. Check scan origin, evidence source,
   review status, topology links, and the route back to the report. In **Scan
   History**, verify queued/failed runs retain their status and each timeline
   item has its own View, JSON, and PDF actions.
6. Verify empty and error states with an empty site and a controlled API
   outage or fixture. Assets, topology, and central jobs must show a loading
   or retry state, not a false "none found" verdict. Restore the API and
   confirm Retry works.
7. At desktop width and 390px/320px mobile widths, check no clipped text,
   horizontal page overflow, hidden Scan/Cancel buttons, covered dialogs, or
   bottom navigation overlap. Use keyboard Tab/Enter/Escape for menus and
   dialogs, and browser Back between the main views.

Record screenshots and any failed action with viewport, browser, role, site,
probe, and time. Step 17 is field-accepted only when the full one-device path
works without an operator guessing the next action. Automated tests and an
HTTP 200 response are supporting checks, not a replacement for this pass.

## Local code and browser check (2026-09-29)

- The dashboard now applies each poll as one site/probe/discovery/scan snapshot.
  A delayed response from the previous site cannot restore its probe data
  after the operator switches sites. A mocked two-site browser check confirmed
  that an empty site's probe origin stays empty after a late prior-site reply.
- Enrollment, revoke, discovery authorization, and Full TCP dialogs now keep
  keyboard focus inside, close with Escape when idle, and return focus to an
  available control. A mocked 320px discovery dialog check covered Tab,
  Shift+Tab, and Escape; no discovery command was submitted.
- Mocked API browser checks found no page-level horizontal overflow on all
  main views at 390px and 1440px, or on Scanner, Assets, and History at 320px.
  Browser Back returned from History to Assets. The web typecheck and local
  web tests passed.
- Switching the Assets site filter now closes an open asset drawer, clears its
  deep-link parameter and stale detail, and loads the new site's inventory.
  A mocked two-site browser check verified this transition and no Assets page
  overflow at 1440px, 390px, or 320px. Web typecheck and 22 local tests passed.
- This is not field acceptance. Repeat the checklist above with each role,
  authorized probe and target, real evidence, reports, and a controlled API
  outage before marking Step 17 complete in the pilot.
