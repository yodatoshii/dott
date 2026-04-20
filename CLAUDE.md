# dott — dev guide for Claude

## what this is
`dott` is a private domain availability checker written in Rust. no middlemen, no tracking. it queries RDAP, WHOIS, and DNS directly from the user's machine.

## workflow rules
- **always bump the version** in `Cargo.toml` when making code changes
- **always tag and push** after bumping to trigger the GitHub Actions release workflow (builds binaries + updates brew formula)
- **never add** unnecessary abstractions, helpers, or over-engineering — keep it tight
- **test locally** with `cargo build` then `./target/debug/dott`, then `cargo install --path .` to update the global command

## how domain checking works

for each domain (`name.tld`), three checks run **in parallel**:

### 1. RDAP (primary)
- hits the TLD-specific RDAP endpoint (defined in `rdap_url()`)
- falls back to `rdap.org` if the primary returns Unknown
- `200` → Taken (also parses the `events` array for expiration date — look for `eventAction` containing `"expir"`)
- `404` → Available (unless body contains "Blocked" → Protected)
- anything else → Unknown

### 2. WHOIS
- hits the WHOIS server on port 43 (defined in `whois_server()`)
- **only add servers that are confirmed working** — dead servers cause 4s timeouts
- parses response text: "no match" / "not found" patterns → Available; "domain name:" / "domain:" → Taken
- for Taken: scans lines for `expir` / `paid-till` / `renewal` keywords, extracts YYYY-MM-DD via `parse_date()`

### 3. DNS
- queries Cloudflare DoH (`cloudflare-dns.com`) for NS records
- `Status 0` (NS records found) → Taken (no expiry date from DNS)
- `Status 3` (NXDOMAIN) → Unknown

### merging the three results
priority order:
1. **DNS Taken overrides everything** (active NS = definitely registered) — but we still try to pull expiry date from RDAP or WHOIS result
2. **RDAP wins over WHOIS** for the status signal — except: if RDAP returns `Taken(None)` and WHOIS returns `Taken(Some(date))`, we keep the WHOIS date
3. **DNS fallback** if both RDAP and WHOIS return Unknown

### result display priority (sort order)
1. Available
2. Unknown
3. Protected
4. Taken

within each group, domains are sorted by TLD rank: `com → io → dev → ai → app → co → net → org → me → so → gg → cc → xyz → cv`

## interactive mode features
- spinner animates while search is in progress
- type `name+` (e.g. `vallley+`) to get prefix/suffix suggestions for that name — bare `+` reuses the last searched name
- type `/help` to show the full command list (search, watchlist, exit)
- suggestions check against `com, io, dev, app, co`
- prefixes: `get try use go my the run hey`
- suffixes: `hq app lab hub base`
