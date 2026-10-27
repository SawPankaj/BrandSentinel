# Changelog

## Private beta hardening

- Replaced simulated identities and client-selected workspaces with authenticated sessions and server-derived memberships.
- Added password hashing, login throttling, CSRF and origin checks, encrypted workspace state and version content, and protected static serving.
- Moved deterministic governance checks and role authorization into the server write path.
- Added administrator team/workspace controls, optimistic concurrency, container deployment files, and security-focused regression tests.
