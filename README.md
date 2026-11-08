# curlp

Wraps `curl` and picks the proxy for each request from a PAC file.

`curlp` looks for a proxy auto-config (PAC) file, evaluates it for the URL of the request, and
runs `curl` with the proxy the PAC selects. It also makes `curl` trust the local certificate
authorities in `~/.config/ssl` next to the standard root certificates.

## Prerequisites

- `curl` in `PATH`
- Go 1.27 or newer, only to build from source

## Installation

Download the binary for the platform from the GitHub releases, or build it:

```bash
go install github.com/audivir/curlp@latest
```

## Usage

Use `curlp` in place of `curl`. All arguments go to `curl`, except the options of `curlp`:

```bash
curlp -L git.example.com
curlp --pac-file ./proxy.pac https://intranet.example.com
```

- `--pac-file <path|uri>` uses this PAC file and skips the search.
- `--curlp-version` prints the version of `curlp`.
- `--curlp-no-ca` skips the additional certificates for this call (see Certificates).
- `CURLP_CURL_PATH` selects the `curl` to run, as a path or as a name looked up in `PATH`. A
  value that cannot be found, or that is `curlp` itself, is an error.
- `-v` shows which PAC file and proxy `curlp` uses, besides the output of `curl`.

`curlp` can be installed under the name `curl` (for example as a symlink earlier in `PATH`). It
skips itself when it searches `PATH` for the real `curl`, whether the file is a symlink or a hard
link. A different copy of `curlp` that is found first stops with an error, because `curlp` sets
`CURLP_ACTIVE` for the `curl` it starts and refuses to run if that variable is set. Set
`CURLP_CURL_PATH` to the real `curl` in that case.

A URL without a scheme is treated as `http`, like `curl` does.

### PAC file

The first match wins:

1. `--pac-file`
1. `$CURLP_PAC_URI`
1. `proxy.pac` in the current directory
1. `$XDG_CONFIG_HOME/curlp/proxy.pac` (or `~/.config/curlp/proxy.pac`)
1. `~/proxy.pac`
1. the automatic proxy configuration URL of macOS, if enabled in the network settings

A PAC location is a path, a `file:` URI, or an `http(s):` URL. Without a PAC file, or if it fails
to load, `curlp` prints a warning and runs `curl` without a proxy.

The proxy of the first usable entry of the result is used. `PROXY` and `HTTP` become `http://`,
`HTTPS` becomes `https://`, `SOCKS` and `SOCKS5` become `socks5://`, and `SOCKS4` becomes
`socks4://`. `DIRECT` as the first entry means no proxy, and later entries are not tried.

The PAC functions `weekdayRange`, `dateRange`, and `timeRange` are not supported. A script that
calls them is reported as an error. Host names inside a PAC script are resolved with the resolver
of Go, which does not use the DNS settings of macOS.

### Certificates

All certificates in `$CURLP_CA_PATH` (a file or a directory, `~/.config/ssl` by default) are
trusted next to the standard roots. Files ending in `.pem`, `.crt`, or `.cer` count, and only
their `CERTIFICATE` blocks, so private keys are never copied. `curlp` writes the combined bundle
to `~/.cache/curlp/ca-bundle.pem` and gives it to `curl` with `--cacert`.

This is skipped if the arguments contain `--cacert`, `--capath`, `-k`, or `--insecure`, or with
`--curlp-no-ca` for a single call. Setting `CURLP_CA_PATH` to an empty value turns it off for
good, while leaving it unset uses `~/.config/ssl`.

Every certificate in that location is trusted by `curlp`, so only put certificate authorities
there that should be trusted.

## License

MIT
