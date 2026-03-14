# dott

private domain search. no middlemen.

## install

```sh
cargo install --git https://github.com/yodatoshii/dott
```

> requires [Rust](https://rustup.rs)

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
