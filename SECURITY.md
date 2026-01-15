# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please open a **private** security advisory on GitHub, or contact the maintainer via the profile listed on the repository.

Do not file public issues for exploitable registration/privilege paths, pipe ACL bypasses, or memory-safety problems until a fix is available.

## Scope notes

Gansi is an AMSI research/monitoring component:

- Registration writes machine-wide COM and AMSI provider keys (admin required).
- Script content may be logged or sent over a local named pipe.
- Treat deployments as high-trust / lab-first unless you harden ACLs and log paths yourself.
