# 🌐 dott


A cli for searching domain names directly from your terminal.

## ✨ Features
Zero Middlemen: Direct connection to WHOIS servers.

Blazing Fast: Written in rust for near-instant results.

Privacy First: No logging, no tracking.

Lightweight: Single binary with zero bloat.

## 🚀 Installation

```sh
curl -fsSL https://raw.githubusercontent.com/yodatoshii/dott/master/install.sh | sh
```

## usage

**interactive mode**
```sh
dott
```

**check a name**
```sh
dott myname
```

**check specific TLDs**
```sh
dott myname --tlds com,io,dev
```

**suggest names from keywords**
```sh
dott --suggest my keywords
```
