# sml-cookie

[![CI](https://github.com/sjqtentacles/sml-cookie/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-cookie/actions/workflows/ci.yml)

RFC 6265 `Cookie` / `Set-Cookie` parsing and building for Standard ML, plus
HMAC-signed (tamper-evident) cookies. Pure, I/O-free, deterministic, and built
test-first against the RFC 6265 / RFC 7231 examples. Dual-compiler:
**MLton + Poly/ML**.

## Features

- **`Cookie.parseCookie`** — parse a request `Cookie:` header value
  (`"a=1; b=2"`) into `(name, value)` pairs.
- **`Cookie.set_cookie`** — a record with the standard `Set-Cookie` attributes:
  `Path`, `Domain`, `Max-Age`, `Expires`, `Secure`, `HttpOnly`, `SameSite`.
- **`Cookie.build` / `Cookie.parseSetCookie`** — serialize / parse a
  `Set-Cookie` value, round-tripping all attributes.
- **`Cookie.httpDate`** — format an IMF-fixdate (`"Sun, 06 Nov 1994 08:49:37 GMT"`,
  RFC 7231 §7.1.1.1) for `Expires`, derived from a [sml-datetime](https://github.com/sjqtentacles/sml-datetime)
  `date` plus a time of day.
- **`SignedCookie`** — cookie values signed with HMAC-SHA256 via
  [sml-crypto](https://github.com/sjqtentacles/sml-crypto); reads verify the
  signature in constant time and reject tampered or wrong-key tokens.

## API

```sml
datatype same_site = Strict | Lax | None

type set_cookie =
  { name : string, value : string
  , path : string option, domain : string option
  , maxAge : int option, expires : string option
  , secure : bool, httpOnly : bool, sameSite : same_site option }

val Cookie.cookie         : string -> string -> set_cookie
val Cookie.parseCookie    : string -> (string * string) list
val Cookie.build          : set_cookie -> string
val Cookie.parseSetCookie : string -> set_cookie option
val Cookie.httpDate       : DateTime.date -> int * int * int -> string

val SignedCookie.sign : { key : string, name : string, value : string } -> Cookie.set_cookie
val SignedCookie.read : { key : string, name : string } -> (string * string) list -> string option
```

## Example

```sml
(* Build a hardened session cookie *)
val sc = { name = "SID", value = "31d4d96e407aad42"
         , path = SOME "/", domain = SOME "example.com"
         , maxAge = SOME 3600, expires = NONE
         , secure = true, httpOnly = true, sameSite = SOME Cookie.Lax }
val header = Cookie.build sc
(* "SID=31d4d96e407aad42; Path=/; Domain=example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Lax" *)

(* Signed cookie round-trip *)
val out   = Cookie.build (SignedCookie.sign { key = "secret", name = "auth", value = "user-42" })
val pairs = Cookie.parseCookie out
val SOME "user-42" = SignedCookie.read { key = "secret", name = "auth" } pairs
```

## Build & test

```sh
make test        # MLton
make test-poly   # Poly/ML
make all-tests   # both
```

**27 deterministic checks**, identical under MLton and Poly/ML.

## Installation

```
package github.com/sjqtentacles/sml-cookie
require {
  github.com/sjqtentacles/sml-http
  github.com/sjqtentacles/sml-crypto
  github.com/sjqtentacles/sml-datetime
}
```

Dependencies are also vendored under `lib/github.com/sjqtentacles/` and
committed, so `make` needs no network.

## Layout

```
lib/github.com/sjqtentacles/sml-cookie/
  cookie.sig  cookie.sml     RFC 6265 parse/build + IMF-fixdate
  signed.sig  signed.sml     HMAC-signed cookies (via sml-crypto)
  sources.mlb sml-cookie.mlb
test/                        Harness suite (27 checks)
```

## License

MIT
