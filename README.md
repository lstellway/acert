# acert

Command-line utility for managing PKI certificates written in Go.

<br />

## Features

<br />

**Manage Your Public Key Infrastructure**

Perform many common tasks necessary for setting up your PKI infrastructure.

-   Generate signing requests
-   Generate authority certificates
-   Generate client certificates
-   Build certificate chains
-   Verify certificate root, chain & hosts
-   Trust certificates

<br />

**Simple, Intuitive API**

A goal of this project is to make PKI simple and approachable.<br />
_(Please don't hesitate to [submit an issue](https://github.com/lstellway/acert/issues) or [open a PR](https://github.com/lstellway/acert/pulls) with your suggestions)_

<br />

**ECDSA Elliptic Curve Support**

Certificates can be signed using [ECDSA Elliptic Curves](https://pkg.go.dev/crypto/ecdsa):

| Standard                                         | Description |
| ------------------------------------------------ | ----------- |
| [P-224](https://pkg.go.dev/crypto/elliptic#P224) | P-224       |
| [P-256](https://pkg.go.dev/crypto/elliptic#P256) | P-256       |
| [P-384](https://pkg.go.dev/crypto/elliptic#P384) | P-384       |
| [P-521](https://pkg.go.dev/crypto/elliptic#P521) | P-521       |

_Note:_<br />
_Be sure to check if the chosen elliptic curve is supported for your use case_<br />
_(eg, [Chrome 42.x does not support P-521](https://bugs.chromium.org/p/chromium/issues/detail?id=478225))_

<br />

**ED25519 Support**

A certificate can be signed with a key using the [ED25519](https://pkg.go.dev/crypto/ed25519@go1.17.1) signature algorithm. <br />

_Note:_<br />
_Be sure to check if your use case supports ED25519 ([good reference](https://ianix.com/pub/ed25519-deployment.html))._<br />
_(eg, ED25519 was introduced in TLS v1.3, which is only [supported by a subset of browsers](https://caniuse.com/tls1-3))_

<br />

## Installation
