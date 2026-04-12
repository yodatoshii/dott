# dott

Private domain availability checker. Queries RDAP, WHOIS, and DNS directly from your machine — no middlemen, no tracking, no API keys.

![dott preview](preview.png)

## Install

**Homebrew**
```sh
brew install yodatoshicom/dott/dott
```

**curl**
```sh
curl -fsSL https://raw.githubusercontent.com/yodatoshicom/dott/master/install.sh | sh
```

**Cargo**
```sh
cargo install dott
```

**From source**
```sh
git clone https://github.com/yodatoshicom/dott
cd dott && cargo install --path .
```

## Usage

**Interactive mode** — just type names, get results:
```sh
dott
```

**Check a name across all TLDs:**
```sh
dott myname
```

**Check specific TLDs:**
```sh
dott myname --tlds com,io,dev
```

**Suggest names from keywords:**
```sh
dott --suggest cool project
```

**Machine-readable output** (for scripts and LLMs):
```sh
dott myname --plain
```
```
myname.com taken
myname.io available
myname.dev available
```

## How it works

For each domain, three checks run in parallel:

| Source | Method | What it tells you |
|--------|--------|-------------------|
| **RDAP** | HTTPS to registry | Status + registration/expiry dates |
| **WHOIS** | TCP port 43 | Status + registration/expiry dates |
| **DNS** | Cloudflare DoH | Whether NS records exist (definitely registered) |

Results are merged with DNS > RDAP > WHOIS priority. Dates are pulled from whichever source has them. Expiring domains are color-highlighted (< 90 days = orange, < 1 year = yellow).

## Supported TLDs

com, net, org, io, dev, app, co, ai, me, so, gg, cc, cv, xyz

## License

[MIT](LICENSE)
