# Licensed dependencies

Production builds require the approved redistribution package at this exact path:

- `nmap-oem.exe`: licensed Windows Nmap OEM installer with unattended `/S` support. The official OEM package includes Npcap OEM and installs both components.

The production release script refuses to continue if this file is missing. Never commit this binary to the repository. Development builds compile without redistributing it and are not suitable for customer deployment.
