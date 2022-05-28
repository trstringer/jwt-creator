# jwt-creator

Quickly and easily create a JWT.

## Installation

```
$ go install github.com/trstringer/jwt-creator@latest
```

## Usage

Create a JWT with a private key:

```
$ jwt-creator \
    --private-key-file myprivatekey.pem \
    --issued-at-now --expires-in-seconds 300 \
    --issuer myissuer
```
