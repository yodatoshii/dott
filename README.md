

![dott preview](preview.png)


# ⚡ Project Overview

dott is a lightweight domain name search CLI with these features:

- ✨ Direct WHOIS connections (no middlemen)
- ⚡ Written in Rust (fast performance)
- 🔒 Privacy-focused (no logging/tracking)
- 📦 Single binary deployment

# 📚 Features Available

- Interactive mode: dott - launches an interactive search
- Direct lookup: dott myname - check different extensions
- Suggestions: dott --suggest my keywords - get name ideas


## 🚀 Installation

**via curl**
```sh
curl -fsSL https://raw.githubusercontent.com/yodatoshii/dott/master/install.sh | sh
```

**build from source**
```sh
git clone https://github.com/yodatoshii/dott
cd dott
cargo install --path .
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
