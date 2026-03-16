# 🌐 dott

![dott preview](preview.png)

A cli for searching domain names directly from your terminal.

## ✨ Features
Zero Middlemen: Direct connection to WHOIS servers.

Blazing Fast: Written in rust for near-instant results.

Privacy First: No logging, no tracking.

Lightweight: Single binary with zero bloat.

## 🚀 Installation

**via curl**
```sh
curl -fsSL https://raw.githubusercontent.com/yodatoshicom/dott/master/install.sh | sh
```

**build from source**
```sh
git clone https://github.com/yodatoshicom/dott
cd dott
cargo install --path .
```

## 💻 usage

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

## 🤖 using with LLMs

dott has a `--plain` flag that outputs clean, no-color text — easy for LLMs to read and act on.

```sh
dott myname --plain
dott myname --tlds com,io,dev --plain
dott --suggest my keywords --plain
```

output:
```
myname.com available
myname.io taken
myname.dev available
```

LLMs can use dott as a tool to check availability while handling the creative/naming side themselves. pass `--plain` so the output is token-efficient and easy to parse.
