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

<br />

**Prebuilt Binaries**

You can download pre-built binaries for your operating system on the [Releases page](https://github.com/lstellway/acert/releases).

<br />

**Homebrew**

The `acert` package is included in the `lstellway/formulae` tap.<br />
To install with homebrew, tap the tap:

```sh
brew tap lstellway/formulae
```

Update taps and install the formula:

```sh
brew update \
    && brew install lstellway/formulae/acert
```

Optionally test the installation:

```sh
brew test lstellway/formulae/acert
```

...and enjoy the brew 🍻

<br />

**Build From Source**

To build from source, download the repository and use the `go build [OPTIONS...]` command.

```sh
git clone https://github.com/lstellway/acert.git \
    && cd acert \
    && go build -ldflags "-X 'main.Version=$(git describe --tags)' -X 'main.ReleaseDate=$(git log -1 --format=%ai $(git describe --tags) | cat)'"
```

This will output the `acert` binary in the directory.<br />
Be sure to move it into a directory included in your `PATH` environment variable.

<br />

## Usage

<br />

Run the `help` command to see available commands and options.

```sh
acert help
```

_More help documentation coming soon..._

<br />

## Versioning

<br />

To show the current version of `acert`, run:

```sh
acert version
```

<br />

**Format**

Versions will be in the `year.month[.revision][-stage]` format.

Examples:

```sh
2021.9.1
2021.10.1-alpha
2021.10.1-beta
2021.10.1-rc
...
```

<br />

**Motivation:**

The [pi-hole docker](https://github.com/pi-hole/docker-pi-hole/) project transitioned to using a format version based on the date in their [`2021.09`](https://github.com/pi-hole/docker-pi-hole/releases/tag/2021.09) release.<br />
This format holds more meaningful information (release date) than incrementing numbers and can be useful for tracking changes.<br />
As mentioned in their release notes, this may not work well if a major (backward-incompatible) update needs to be shipped.<br />
Their solution for this is to wait until the start of a new month to ship major updates.<br />
The scope of this project is fairly limited, so I believe this versioning format should work just fine.
