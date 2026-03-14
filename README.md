# dott


A cli to search for domain names, directly from your terminal.

## install

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
