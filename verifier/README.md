# pageverified-verify

Check a PageVerified capture record on your own computer.

One file, MIT licence, Node.js 20 or newer. It installs nothing and makes no network calls. Once
you hold the record and its tokens, you do not need PageVerified to check them. The PageVerified
server runs this same file for its own `/verify` page, so the two cannot disagree.

## Quick start

```sh
# 1. Get the script, PageVerified's public keys and the record.
curl -s -o pageverified-verify.mjs https://pageverified.com/verify/pageverified-verify.mjs
curl -s -o keys.json https://pageverified.com/.well-known/pageverified-keys.json
curl -s -o record.json https://pageverified.com/api/v1/verify/<record id>

# 2. Check it, with your own copy of the captured file.
node pageverified-verify.mjs record.json --keys keys.json --file capture.png
```

Download `keys.json` yourself, from PageVerified, and keep it. If you leave out `--keys`, the
script uses the key inside `record.json` and reports the signature as `NOT TRUSTED`: a key that
arrives inside the file being checked proves nothing, because whoever made the file chose it.

`record.json` is the JSON answer of `GET /api/v1/verify/<record id>`. It holds the record,
PageVerified's signature, the public keys, and each outside timestamp token with the authority's
root certificate. A capture made with `"public_receipt": false` is not found by id: send the
record you were given to `POST /api/v1/verify` and save that answer instead.

Exit code `0` means every check that ran passed, `1` means a check failed or could not be
trusted, `2` means the input could not be read.

## Options

| Option | What it does |
| --- | --- |
| `--file <path>` | Hashes your copy of the captured file and compares it with the record. |
| `--keys <path>` | PageVerified's public key set (JWKS), downloaded by you. Needed for the signature to count as a pass. |
| `--roots <path>` | Uses root certificates (PEM) that you trust for the outside timestamps, instead of the ones inside `record.json`. |
| `--export <dir>` | Writes the files OpenSSL needs and prints the commands. |
| `--json` | Prints the result as JSON. |

## What each check proves, and what it does not

| Check | Proves | Does not prove |
| --- | --- | --- |
| PageVerified signature | PageVerified's key signed these exact record fields, so none of them has been changed since. | The time in the record is PageVerified's own clock. The signature does not show who wrote the page or that what the page says is true. |
| Content hash | A file with this SHA-256 is byte for byte the file the record describes. | It says nothing about what the live page shows now, or about who wrote it. |
| Outside timestamp | An authority that PageVerified does not run signed the SHA-256 of this exact record at the time shown. The record existed by then and has not been changed since. | The authority saw only a hash. It did not see the page, the URL or the file, and it does not vouch for them. The check does not look up whether the authority's certificate was later revoked. |

None of this is a legal certification.

A record with no outside timestamp is still checked for its signature and content hash. The
script says plainly that it has no outside timestamp. Its time then rests on PageVerified's own
clock.

## What the script trusts

**PageVerified's public key.** The signature counts as a pass only against a key set you pass
with `--keys`. Get it from `https://pageverified.com/.well-known/pageverified-keys.json` and keep
your copy. The script prints the key's thumbprint (RFC 7638) so you can compare copies. Without
`--keys` the result is `NOT TRUSTED` and the exit code is `1`.

**The authorities' root certificates.** A token is reported under an authority's name only when
it chains to a root certificate whose SHA-256 is listed in `KNOWN_ROOTS` at the top of the script.
A token that chains to any other root is reported as `NOT TRUSTED` unless you pass that root
yourself with `--roots`, and then it is shown as an unrecognised authority: the script never
takes an authority's name from the file being checked. Check the listed values against the authorities' own sites before you
rely on them:

| Authority | Root certificate SHA-256 | Where the authority publishes it |
| --- | --- | --- |
| FreeTSA | `a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc` | `https://freetsa.org/files/cacert.pem`, linked from `https://freetsa.org/` |
| CNX Timestamp Authority | `8dbd2540ac160c527584e0656b6b0e9636e91da0e70afe3c4bdee54175825479` | Inside every token it issues. The SHA-256 of its public key, `9b9bf33f16e83c4302712dd1661da46bbe037c4df705176a1232f90efed87ca1`, is published at `https://tsa.cnx.net.kh/validation.html` and in the DNS TXT record `_ca.cnx.net.kh`. |

These values were read from the authorities' own pages on 2026-11-11.

## The same check with OpenSSL

An outside timestamp is a standard RFC 3161 token. You can check it with OpenSSL alone.

```sh
node pageverified-verify.mjs record.json --export out
cd out
openssl ts -verify -data record.canonical.json -in freetsa.tsr -CAfile freetsa-root.pem
# Verification: OK
```

What the files are:

- `record.canonical.json`: the record as JSON with its keys sorted and no spaces. These are the
  exact bytes PageVerified signed. Their SHA-256 is the only thing an authority was ever sent.
- `<authority>.tsr`: the authority's answer, byte for byte as it was received.
- `<authority>-root.pem`: the authority's root certificate.

Without the script: `record.json` lists each token as `token_base64` and each root as
`root_certificates_pem`. Decode the token from base64 into `<authority>.tsr`, save the root as
`<authority>-root.pem`, and use the hash instead of the file:

```sh
openssl ts -verify -digest <record_sha256> -in freetsa.tsr -CAfile freetsa-root.pem
```

To read what a token says, including the time: `openssl ts -reply -in freetsa.tsr -text`.

## How a record is checked

1. **Signature.** The record is serialised as JSON with sorted keys and no spaces. The signature
   is base64url. `alg` is `EdDSA` (Ed25519) or `ES256` (ECDSA P-256, raw 64-byte `r` and `s`).
   The key is looked up by `key_id` in the key set.
2. **Content hash.** With `--file`, the SHA-256 of your file must equal `record.sha256`.
3. **Outside timestamp.** For each token: the answer must be "granted"; the token must be a CMS
   SignedData holding a TSTInfo; the signed attributes must name the signing certificate by its
   hash; the signature must verify with that certificate; the certificate must be for
   time-stamping and valid at the stated time; it must chain to a trusted root through
   certificates allowed to issue certificates; and the token's SHA-256 imprint must equal the
   SHA-256 of the canonical record.

Supported signature algorithms: RSA PKCS#1 v1.5 and ECDSA with SHA-256, SHA-384 or SHA-512, and
Ed25519. SHA-1 signatures are refused.

## Limits

- Certificate revocation is not checked. Neither OCSP nor CRLs are fetched, because the script
  makes no network calls.
- A token shows that the record existed by the authority's time. The capture time inside the
  record is still PageVerified's clock.
- Records made before outside timestamps were switched on have no token and do not get one later.
- OpenTimestamps proofs are not produced by PageVerified and are not read by this script.

## Licence

MIT. The licence text is at the top of `pageverified-verify.mjs`.
