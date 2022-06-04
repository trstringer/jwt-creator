# jwt-creator

Quickly and easily create and verify JWTs.

## Installation

```
$ go install github.com/trstringer/jwt-creator@latest
```

## Create a JWT

```
$ jwt-creator create \
    --private-key-file myprivatekey.pem \
    --issued-at-now --expires-in-seconds 300 \
    --issuer myissuer
```

## Verify a JWT

```
$ jwt-creator verify \
    --public-key-file mypublickey.pem \
    --token <jwt>
```
