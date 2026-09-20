# Security model

No public registration. Administrator/viewer roles are checked by API dependencies, not just hidden buttons. Passwords use Argon2id. Login is rate-limited by address and normalized account; enrollment by address. Both fail closed when Redis cannot enforce the limit. Ingest remains available without Redis because PostgreSQL is the durable source of truth.

Sessions are opaque random tokens stored hashed in PostgreSQL, expire after eight hours, and are revoked on logout. Secure HttpOnly SameSite Strict cookies hold sessions. CSRF tokens are required for authenticated mutations; refresh rotates the session. Agent/probe tokens are independent, randomly generated and stored only as SHA-256 hashes centrally. Bearer requests require the matching identity header and kind. One-time enrollment consumes its token atomically. Revocation disables one identity. An admin-bound VPS enrollment token supports credential rotation while preserving the stable VPS identity and revoking older credentials.

Agent/probe outbound HTTPS verifies certificates, forbids redirects and has timeouts/bounded responses. The explicit unsafe development switch is only for isolated local testing. Production endpoints should be reachable only through the HTTPS reverse proxy. Agent files are mode 0600. Never place real credentials in Git, screenshots, application logs or support bundles.

Ingest limits compressed bodies to 1 MiB, expanded bodies to 4 MiB, and batches to 1,000 rows. Types, IP addresses, domains, ports and aware timestamps are checked. Batch receipts prevent duplicates; conflicting reused IDs fail. No permissive CORS is installed. Vue escapes user-supplied content. CSV formula prefixes are neutralized. Search is bounded and SQL uses ORM parameterization.

Application containers run without root and drop Linux capabilities where applicable. PostgreSQL/Redis use private Compose networking. Read-only app containers have tmpfs for temporary files. Health endpoints contain no user browsing data; metrics require a session. Sensitive admin mutations and exports are recorded in the admin audit log.

This platform is sensitive operational metadata storage. Assign viewer accounts deliberately, set realistic retention, restrict host access, and protect backups. Source IPs can be shared by NAT, VPNs and households; do not equate an address with an individual.
