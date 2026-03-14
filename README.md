# dott

private domain search. no middlemen.

## install

**homebrew**
```sh
brew tap yodatoshii/dott
brew install dott
```

**cargo**
```sh
cargo install --git https://github.com/yodatoshii/dott
```

> cargo requires [Rust](https://rustup.rs)

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
