# Step 24: Customer isolation and read scaling

## Supported deployment boundary

Run **one ForgeSec control plane, PostgreSQL database, runtime volume, public
hostname, and operator directory per customer**. A site is an authorization
scope for network jobs, **not** a tenant. Do not create sites for unrelated
customers in one deployment or give a customer account access to a shared
ForgeSec instance. Global admin/operator/viewer roles still see all sites in
their deployment. Shared-database multitenancy, per-customer roles, SSO/MFA,
row-level security, and cross-tenant billing are not implemented.

Set a unique, stable lowercase `FORGESEC_CUSTOMER_ID` (3-64 characters) in each
production deployment. Also use a unique `FORGESEC_COMPOSE_PROJECT` and a
dedicated host/VM or separately managed ingress and volumes. The standard Caddy
overlay binds ports 80/443 and therefore cannot be run twice on one host as-is.
Do not share a PostgreSQL URL, database, volume, runtime directory, or user
credentials between customers. The customer ID is a safety label, **not** a
secret or an access-control token.

At API/bootstrap startup the ID is bound in the `deployment` collection. A
different or missing ID against a bound store stops startup before legacy
migration/backfill. A fresh empty store binds automatically. For existing
unbound data, first take and verify a backup, confirm the store belongs to the
specified customer, then set `FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA=true` for
**one** startup. Remove that setting immediately afterward. This explicit
adoption does not split or sanitize mixed-customer data. If multiple customers
already share one store, stop and plan a reviewed data migration; do not adopt
it as one customer. Changing the label later is intentionally unsupported.

## Scale limits

PostgreSQL now has indexes for asset site/time, observation asset/site,
worker-job site/asset, and approved-scope site queries. Asset lists use SQL
count, filtering, ordering, and paging instead of loading the full collection.
Asset timelines, device depth, evidence, topology, scope checks, and worker
polling read only the relevant asset or site documents. Local JSON mode keeps
the same API behavior but still scans files; it is for development/pilots, not
large fleets.

The generic document store, some dashboard rollups, NVD refreshes, and the
global PostgreSQL advisory transaction lock remain scaling constraints. Run
**one API worker** per deployment. Do not increase `uvicorn --workers` or API
replicas on the strength of these read indexes alone. Before a large fleet,
benchmark representative sites, add retention/archive policies, replace
remaining full-document scans with indexed queries, and prove queue lease and
concurrent-write behavior under load. The optional PostgreSQL integration test
requires `FORGESEC_TEST_DATABASE_URL`; local unit tests do not validate index
plans against a production-sized database.
