# Telesec architecture

## Runtime components

Telesec has four processes. The Next.js dashboard is an operator interface, the FastAPI service owns JSON state and the command queue, one native Windows service runs inside each authorized site or network, and a separate per-user tray companion reports that service's state. The agent makes outbound HTTP(S) requests only. Nmap and Npcap run on the Windows agent machine, never in the web or API containers. Closing the tray does not stop the service.

The v1 server deliberately has no human account database. For a local deployment, web and API ports bind to loopback. Agent identity is still authenticated: the dashboard creates a short-lived, single-use enrollment token, the agent exchanges it for a random machine credential, and only a hash of that credential is stored by the API. The Windows agent protects its credential with DPAPI.

## Data flow

1. An operator creates an enrollment token and downloads the Windows setup EXE.
2. Setup installs licensed Npcap/Nmap packages when they are absent, writes a protected bootstrap file, installs one Windows service, and starts it.
3. The service consumes the token, stores its DPAPI-protected machine credential, and sends heartbeats.
4. After explicit authorization, the API queues a lightweight private `/24` discovery command.
5. The agent uploads discovered hosts. The operator selects at most 10 non-agent devices.
6. The API resolves those stable device IDs to immutable IP targets and queues one scan job.
7. One scheduler runs up to three Nmap child processes concurrently and uploads progress and evidence-based results.

## Storage and limits

The API stores collections as atomic JSON files beneath `services/api/runtime-data` or the `telesec-runtime` Docker volume. Run exactly one API worker and one API container. Back up the whole runtime directory as one unit. The scan target limit is fixed at 10 in both UI and API, and the agent concurrency is fixed at three.

No exploit execution, credential attacks, brute force, or aggressive NSE scripts are part of this product. Device classification and exposure flags are observations based on scan evidence, not vulnerability claims.
