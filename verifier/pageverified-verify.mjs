#!/usr/bin/env node
// SPDX-License-Identifier: MIT
//
// MIT License
//
// Copyright (c) 2026 PageVerified
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
// BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// pageverified-verify: checks a PageVerified capture record offline.
//
// One file. Node 20 or newer. No packages to install and no network calls.
//
//   node pageverified-verify.mjs record.json --keys keys.json
//   node pageverified-verify.mjs record.json --keys keys.json --file capture.png
//   node pageverified-verify.mjs record.json --keys keys.json --roots roots.pem
//   node pageverified-verify.mjs record.json --export out/      (writes files for openssl)
//   node pageverified-verify.mjs record.json --json
//
// record.json is the answer from https://pageverified.com/api/v1/verify/<record id>, saved to a
// file. It holds the record, PageVerified's signature and each outside timestamp token.
// keys.json is PageVerified's public key set, which you download yourself from
// https://pageverified.com/.well-known/pageverified-keys.json. Without --keys the signature is
// reported as NOT TRUSTED, because a key found inside the file being checked proves nothing.
// See README.md for what each check proves and what it does not.
//
// What is checked:
//   1. PageVerified's signature over the record (Ed25519 or ECDSA P-256).
//   2. With --file: that your file's SHA-256 equals the hash in the record.
//   3. Each outside timestamp (RFC 3161): the token is signed by the authority's certificate,
//      that certificate chains to a root you trust, the certificate was valid at the stated
//      time, and the token covers the SHA-256 of this exact record.
//
// What is not checked: certificate revocation, and anything about the content of the page.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const VERIFIER_VERSION = "1.0.0";

// Root certificates of the outside authorities PageVerified has used, by SHA-256 of the
// certificate (DER). A token that chains to one of these is reported under the authority's name.
// A token that chains to any other root is reported as "untrusted" unless you pass that root
// yourself with --roots. Compare these values with the authority's own website before relying
// on them: README.md says where each one is published.
export const KNOWN_ROOTS = Object.freeze({
  a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc: "FreeTSA",
  "8dbd2540ac160c527584e0656b6b0e9636e91da0e70afe3c4bdee54175825479": "CNX Timestamp Authority",
});
// The same roots by the short id PageVerified uses for each authority.
export const KNOWN_ROOT_IDS = Object.freeze({
  a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc: "freetsa",
  "8dbd2540ac160c527584e0656b6b0e9636e91da0e70afe3c4bdee54175825479": "cnx",
});

// ---------------------------------------------------------------------------------------
// The record and PageVerified's signature
// ---------------------------------------------------------------------------------------

const RECORD_FIELDS = ["v", "call_id", "url", "format", "full_page", "sha256", "bytes", "captured_at", "renderer", "key_id", "alg"];

// The exact bytes that are signed and timestamped: the record as JSON with its keys sorted and
// no spaces. A record holds only strings, whole numbers and true/false.
export function canonicalize(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) throw new TypeError("record_must_be_object");
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalValue(record[key], key)}`).join(",")}}`;
}

function canonicalValue(value, key) {
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  throw new TypeError(`unsupported_record_value:${key}`);
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// SHA-256 of the canonical record. This is the value sent to the outside authorities.
export function recordDigestHex(record) {
  return sha256Hex(Buffer.from(canonicalize(record), "utf8"));
}

// Checks { record, signature } against a JSON Web Key Set. Never throws.
export function verifyRecordSignature(signed, jwks) {
  try {
    const record = signed?.record;
    const signature = signed?.signature;
    if (!record || typeof record !== "object" || Array.isArray(record)) return { valid: false, reason: "record_missing" };
    if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{40,200}$/.test(signature)) return { valid: false, reason: "signature_missing" };
    const extra = Object.keys(record).filter((key) => !RECORD_FIELDS.includes(key));
    const missing = RECORD_FIELDS.filter((key) => !(key in record));
    if (extra.length || missing.length) return { valid: false, reason: "record_shape_invalid" };
    if (record.v !== 1) return { valid: false, reason: "record_version_unsupported" };
    const jwk = (Array.isArray(jwks?.keys) ? jwks.keys : []).find((key) => key?.kid === record.key_id);
    if (!jwk) return { valid: false, reason: "unknown_key_id" };
    const alg = jwk.kty === "OKP" && jwk.crv === "Ed25519" ? "EdDSA" : jwk.kty === "EC" && jwk.crv === "P-256" ? "ES256" : null;
    if (alg !== record.alg) return { valid: false, reason: "alg_mismatch" };
    const publicKey = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ...(jwk.kty === "EC" ? { y: jwk.y } : {}) }, format: "jwk" });
    const bytes = Buffer.from(canonicalize(record), "utf8");
    const sig = Buffer.from(signature, "base64url");
    const ok = alg === "EdDSA"
      ? cryptoVerify(null, bytes, publicKey, sig)
      : cryptoVerify("sha256", bytes, { key: publicKey, dsaEncoding: "ieee-p1363" }, sig);
    return ok ? { valid: true, key_id: record.key_id, alg, key_thumbprint: jwkThumbprint(jwk) } : { valid: false, reason: "signature_mismatch" };
  } catch {
    return { valid: false, reason: "record_invalid" };
  }
}

// RFC 7638 thumbprint, so a key can be compared with the published key set by eye.
export function jwkThumbprint(jwk) {
  const members = jwk.kty === "EC" ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y } : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return createHash("sha256").update(JSON.stringify(members)).digest("base64url");
}

// ---------------------------------------------------------------------------------------
// A small DER reader (definite lengths only, which is all DER allows)
// ---------------------------------------------------------------------------------------

const TAG = { BOOLEAN: 0x01, INTEGER: 0x02, BITS: 0x03, OCTETS: 0x04, OID: 0x06, UTC: 0x17, GENERALIZED: 0x18, SEQUENCE: 0x30, SET: 0x31 };

function node(buf, offset, limit = buf.length) {
  if (offset + 2 > limit) throw new Error("der_truncated");
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error("der_long_tag");
  let length = buf[offset + 1];
  let header = 2;
  if (length === 0x80) throw new Error("der_indefinite_length");
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count > 4 || offset + 2 + count > limit) throw new Error("der_bad_length");
    length = 0;
    for (let index = 0; index < count; index += 1) length = length * 256 + buf[offset + 2 + index];
    header = 2 + count;
  }
  const start = offset + header;
  const end = start + length;
  if (end > limit) throw new Error("der_truncated");
  return { tag, offset, start, end };
}

function children(buf, parent) {
  const out = [];
  let at = parent.start;
  while (at < parent.end) {
    const child = node(buf, at, parent.end);
    out.push(child);
    at = child.end;
  }
  return out;
}

const whole = (buf, item) => buf.subarray(item.offset, item.end);
const inner = (buf, item) => buf.subarray(item.start, item.end);

function expect(item, tag, what) {
  if (!item || item.tag !== tag) throw new Error(`der_unexpected:${what}`);
  return item;
}

function readOid(buf, item) {
  expect(item, TAG.OID, "oid");
  const bytes = inner(buf, item);
  if (!bytes.length) throw new Error("der_empty_oid");
  const parts = [];
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 7n) | BigInt(byte & 0x7f);
    if (!(byte & 0x80)) {
      parts.push(value);
      value = 0n;
    }
  }
  const first = parts[0] < 80n ? parts[0] / 40n : 2n;
  return [first, parts[0] - first * 40n, ...parts.slice(1)].join(".");
}

function readIntegerHex(buf, item) {
  expect(item, TAG.INTEGER, "integer");
  const hex = inner(buf, item).toString("hex").replace(/^(?:00)+(?=[0-9a-f]{2})/, "");
  return hex || "00";
}

function readTime(buf, item) {
  const text = inner(buf, item).toString("latin1");
  let match;
  if (item.tag === TAG.UTC && (match = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/))) {
    const year = Number(match[1]) < 50 ? `20${match[1]}` : `19${match[1]}`;
    return new Date(`${year}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`);
  }
  if (item.tag === TAG.GENERALIZED && (match = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/))) {
    const millis = match[7] ? `.${match[7].padEnd(3, "0").slice(0, 3)}` : "";
    return new Date(`${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}${millis}Z`);
  }
  throw new Error("der_bad_time");
}

// ---------------------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------------------

const HASH_BY_OID = Object.freeze({
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
});

// Signature algorithms accepted on tokens and certificates. SHA-1 signatures are refused.
const SIGNATURE_BY_OID = Object.freeze({
  "1.2.840.113549.1.1.1": { hash: null }, // RSA; the hash is named beside it
  "1.2.840.113549.1.1.11": { hash: "sha256" },
  "1.2.840.113549.1.1.12": { hash: "sha384" },
  "1.2.840.113549.1.1.13": { hash: "sha512" },
  "1.2.840.10045.4.3.2": { hash: "sha256" },
  "1.2.840.10045.4.3.3": { hash: "sha384" },
  "1.2.840.10045.4.3.4": { hash: "sha512" },
  "1.3.101.112": { hash: null, ed25519: true },
});

const OID = Object.freeze({
  signedData: "1.2.840.113549.1.7.2",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingCertificate: "1.2.840.113549.1.9.16.2.12",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  timeStamping: "1.3.6.1.5.5.7.3.8",
  extKeyUsage: "2.5.29.37",
  keyUsage: "2.5.29.15",
  basicConstraints: "2.5.29.19",
  commonName: "2.5.4.3",
  organization: "2.5.4.10",
});

function checkSignature(algorithmOid, namedHash, data, publicKey, signature) {
  const spec = SIGNATURE_BY_OID[algorithmOid];
  if (!spec) return false;
  const hash = spec.hash || namedHash;
  if (!spec.ed25519 && (!hash || hash === "sha1")) return false;
  try {
    return cryptoVerify(spec.ed25519 ? null : hash, data, publicKey, signature);
  } catch {
    return false;
  }
}

export function parseCertificate(der) {
  const buf = Buffer.from(der);
  const top = expect(node(buf, 0), TAG.SEQUENCE, "certificate");
  if (top.end !== buf.length) throw new Error("der_trailing_bytes");
  const [tbs, signatureAlgorithm, signatureBits] = children(buf, top);
  const fields = children(buf, expect(tbs, TAG.SEQUENCE, "tbs"));
  const base = fields[0]?.tag === 0xa0 ? 1 : 0;
  const [serial, , issuer, validity, subject, spki] = fields.slice(base);
  const [notBefore, notAfter] = children(buf, expect(validity, TAG.SEQUENCE, "validity"));
  const cert = {
    der: buf,
    sha256: sha256Hex(buf),
    tbs: whole(buf, tbs),
    serialHex: readIntegerHex(buf, serial),
    issuerRaw: whole(buf, expect(issuer, TAG.SEQUENCE, "issuer")),
    subjectRaw: whole(buf, expect(subject, TAG.SEQUENCE, "subject")),
    notBefore: readTime(buf, notBefore),
    notAfter: readTime(buf, notAfter),
    publicKey: createPublicKey({ key: whole(buf, expect(spki, TAG.SEQUENCE, "spki")), format: "der", type: "spki" }),
    signatureAlgorithm: readOid(buf, children(buf, expect(signatureAlgorithm, TAG.SEQUENCE, "signature algorithm"))[0]),
    signature: inner(buf, expect(signatureBits, TAG.BITS, "signature")).subarray(1),
    isCa: false,
    keyUsage: null,
    extendedKeyUsage: null,
    commonName: null,
    organization: null,
  };
  for (const set of children(buf, subject)) {
    for (const pair of children(buf, set)) {
      const [type, value] = children(buf, pair);
      const name = readOid(buf, type);
      if (name === OID.commonName) cert.commonName = inner(buf, value).toString("utf8");
      if (name === OID.organization) cert.organization = inner(buf, value).toString("utf8");
    }
  }
  const extensions = fields.slice(base + 6).find((field) => field.tag === 0xa3);
  for (const extension of extensions ? children(buf, children(buf, extensions)[0]) : []) {
    const parts = children(buf, extension);
    const name = readOid(buf, parts[0]);
    const value = inner(buf, expect(parts[parts.length - 1], TAG.OCTETS, "extension value"));
    if (name === OID.basicConstraints) {
      const flags = children(value, expect(node(value, 0), TAG.SEQUENCE, "basic constraints"));
      cert.isCa = flags[0]?.tag === TAG.BOOLEAN && value[flags[0].start] !== 0;
    }
    if (name === OID.extKeyUsage) {
      cert.extendedKeyUsage = children(value, expect(node(value, 0), TAG.SEQUENCE, "extended key usage")).map((item) => readOid(value, item));
    }
    if (name === OID.keyUsage) {
      const bits = inner(value, expect(node(value, 0), TAG.BITS, "key usage"));
      cert.keyUsage = { keyCertSign: bits.length > 1 && Boolean(bits[1] & 0x04) };
    }
  }
  return cert;
}

// PEM text (one or more certificates) to DER buffers.
export function pemToDer(pem) {
  const blocks = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return blocks.map((block) => Buffer.from(block.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""), "base64"));
}

export function derToPem(der) {
  const lines = Buffer.from(der).toString("base64").match(/.{1,64}/g) || [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

// ---------------------------------------------------------------------------------------
// RFC 3161 time-stamp tokens
// ---------------------------------------------------------------------------------------

// Accepts a TimeStampResp (what an authority answers, and what `openssl ts -verify -in` reads) or
// a bare TimeStampToken. Returns { status, token } where token is the ContentInfo bytes or null.
export function readTimestampResponse(bytes) {
  const buf = Buffer.from(bytes);
  const top = expect(node(buf, 0), TAG.SEQUENCE, "response");
  if (top.end !== buf.length) throw new Error("der_trailing_bytes");
  const parts = children(buf, top);
  if (parts[0]?.tag === TAG.OID) return { status: 0, token: buf };
  const status = Number.parseInt(readIntegerHex(buf, children(buf, expect(parts[0], TAG.SEQUENCE, "status"))[0]), 16);
  return { status, token: parts[1] ? whole(buf, parts[1]) : null };
}

function fail(reason) {
  return { valid: false, reason };
}

// Bounds on the work one token can cause. Real authorities send two or three certificates.
const MAX_POOL_CERTIFICATES = 8;
const MAX_CHAIN_DEPTH = 4;

// Where the token's own certificate list sits inside an authority's answer: the whole
// `certificates [0]` field of the CMS SignedData, as { start, end } byte offsets, or null when the
// answer carries none. That field is not covered by the signature, so a server may store it once
// per authority and splice it back in, which gives back the exact bytes that were received.
export function locateCertificateField(bytes) {
  try {
    const buf = Buffer.from(bytes);
    const top = expect(node(buf, 0), TAG.SEQUENCE, "response");
    const parts = children(buf, top);
    const tokenNode = parts[0]?.tag === TAG.OID ? top : parts[1];
    if (!tokenNode) return null;
    const [contentType, content] = children(buf, expect(tokenNode, TAG.SEQUENCE, "content info"));
    if (readOid(buf, contentType) !== OID.signedData) return null;
    const signedData = children(buf, expect(children(buf, expect(content, 0xa0, "content"))[0], TAG.SEQUENCE, "signed data"));
    const field = signedData.slice(3, -1).find((item) => item.tag === 0xa0);
    return field ? { start: field.offset, end: field.end } : null;
  } catch {
    return null;
  }
}

// Verifies one token. `roots` are the root certificates you trust for this authority (DER
// buffers or PEM text). `digestHex` is the SHA-256 the token must cover. Never throws.
//   { valid: true, attested_time, serial, policy_oid, signer_common_name, signer_organization,
//     root_sha256, nonce }
//   { valid: false, reason }
export function verifyTimestampToken(bytes, { digestHex, roots = [], nonceHex = null } = {}) {
  try {
    return verifyToken(bytes, { digestHex, roots, nonceHex });
  } catch {
    return fail("token_unreadable");
  }
}

function verifyToken(bytes, { digestHex, roots, nonceHex }) {
  if (!/^[0-9a-f]{64}$/.test(String(digestHex || ""))) return fail("digest_required");
  const trusted = roots.flatMap((root) => (typeof root === "string" ? pemToDer(root) : [root])).map((der) => parseCertificate(der));
  if (!trusted.length) return fail("no_trusted_roots");

  const response = readTimestampResponse(bytes);
  // 0 is granted, 1 is granted with modifications. Anything else carries no token to rely on.
  if (response.status !== 0 && response.status !== 1) return fail("not_granted");
  if (!response.token) return fail("token_missing");

  const buf = response.token;
  const [contentType, content] = children(buf, expect(node(buf, 0), TAG.SEQUENCE, "content info"));
  if (readOid(buf, contentType) !== OID.signedData) return fail("not_a_timestamp_token");
  const signedData = children(buf, expect(children(buf, expect(content, 0xa0, "content"))[0], TAG.SEQUENCE, "signed data"));
  const encapsulated = children(buf, expect(signedData[2], TAG.SEQUENCE, "encapsulated content"));
  if (readOid(buf, encapsulated[0]) !== OID.tstInfo) return fail("not_a_timestamp_token");
  const tstInfo = inner(buf, expect(children(buf, expect(encapsulated[1], 0xa0, "content"))[0], TAG.OCTETS, "tst info"));
  const certificateSet = signedData.slice(3).find((item) => item.tag === 0xa0);
  const signerInfos = children(buf, expect(signedData[signedData.length - 1], TAG.SET, "signer infos"));
  if (signerInfos.length !== 1) return fail("signer_count_unsupported");
  const pool = [];
  for (const item of certificateSet ? children(buf, certificateSet) : []) {
    // Anything in the set that is not a plain certificate is ignored.
    if (item.tag !== TAG.SEQUENCE) continue;
    if (pool.length >= MAX_POOL_CERTIFICATES) break; // no real chain is longer; more would only cost time
    try { pool.push(parseCertificate(whole(buf, item))); } catch { /* an unreadable extra certificate cannot help or harm */ }
  }

  // The signer.
  const signer = children(buf, expect(signerInfos[0], TAG.SEQUENCE, "signer info"));
  const signerId = signer[1];
  const digestAlgorithm = HASH_BY_OID[readOid(buf, children(buf, expect(signer[2], TAG.SEQUENCE, "digest algorithm"))[0])];
  if (!digestAlgorithm || digestAlgorithm === "sha1") return fail("digest_algorithm_unsupported");
  const signedAttributes = expect(signer[3], 0xa0, "signed attributes");
  const signatureAlgorithm = readOid(buf, children(buf, expect(signer[4], TAG.SEQUENCE, "signature algorithm"))[0]);
  const signature = inner(buf, expect(signer[5], TAG.OCTETS, "signature"));

  const attributes = new Map();
  for (const attribute of children(buf, signedAttributes)) {
    const [type, values] = children(buf, attribute);
    attributes.set(readOid(buf, type), children(buf, expect(values, TAG.SET, "attribute values"))[0]);
  }
  const typeAttribute = attributes.get(OID.contentType);
  if (!typeAttribute || readOid(buf, typeAttribute) !== OID.tstInfo) return fail("content_type_mismatch");
  const digestAttribute = attributes.get(OID.messageDigest);
  if (!digestAttribute || !inner(buf, digestAttribute).equals(createHash(digestAlgorithm).update(tstInfo).digest())) return fail("message_digest_mismatch");

  let signerCert;
  if (signerId.tag === TAG.SEQUENCE) {
    const [issuer, serial] = children(buf, signerId);
    const issuerRaw = whole(buf, issuer);
    const serialHex = readIntegerHex(buf, serial);
    signerCert = [...pool, ...trusted].find((cert) => cert.serialHex === serialHex && cert.issuerRaw.equals(issuerRaw));
  }
  // The signed attributes must name the signing certificate by its hash (RFC 3161 section 2.4.2).
  const essV2 = attributes.get(OID.signingCertificateV2);
  const essV1 = attributes.get(OID.signingCertificate);
  if (!essV2 && !essV1) return fail("signing_certificate_attribute_missing");
  const essCert = children(buf, children(buf, children(buf, essV2 || essV1)[0])[0]);
  let essHash = essV2 ? "sha256" : "sha1";
  let essIndex = 0;
  if (essV2 && essCert[0].tag === TAG.SEQUENCE) {
    essHash = HASH_BY_OID[readOid(buf, children(buf, essCert[0])[0])];
    essIndex = 1;
  }
  if (!essHash) return fail("signing_certificate_attribute_unsupported");
  const namedHash = inner(buf, expect(essCert[essIndex], TAG.OCTETS, "certificate hash"));
  const matchesNamed = (cert) => createHash(essHash).update(cert.der).digest().equals(namedHash);
  signerCert ||= [...pool, ...trusted].find(matchesNamed);
  if (!signerCert) return fail("signer_certificate_missing");
  if (!matchesNamed(signerCert)) return fail("signing_certificate_attribute_mismatch");

  // The signature is over the signed attributes, re-tagged as a SET.
  const signedBytes = Buffer.from(whole(buf, signedAttributes));
  signedBytes[0] = TAG.SET;
  if (!checkSignature(signatureAlgorithm, digestAlgorithm, signedBytes, signerCert.publicKey, signature)) return fail("signature_invalid");

  // What the authority signed.
  const info = children(tstInfo, expect(node(tstInfo, 0), TAG.SEQUENCE, "tst info"));
  const imprint = children(tstInfo, expect(info[2], TAG.SEQUENCE, "message imprint"));
  if (HASH_BY_OID[readOid(tstInfo, children(tstInfo, imprint[0])[0])] !== "sha256") return fail("imprint_algorithm_unsupported");
  if (inner(tstInfo, expect(imprint[1], TAG.OCTETS, "imprint")).toString("hex") !== digestHex) return fail("imprint_mismatch");
  const time = readTime(tstInfo, expect(info[4], TAG.GENERALIZED, "time"));
  const nonceItem = info.slice(5).find((item) => item.tag === TAG.INTEGER);
  const nonce = nonceItem ? readIntegerHex(tstInfo, nonceItem) : null;
  if (nonceHex !== null && nonce !== String(nonceHex).toLowerCase().replace(/^(?:00)+(?=[0-9a-f]{2})/, "")) return fail("nonce_mismatch");

  // The signer's certificate: for time-stamping only, valid at the stated time, and chained to
  // a trusted root through certificates that are allowed to issue certificates.
  if (!signerCert.extendedKeyUsage?.includes(OID.timeStamping)) return fail("signer_not_for_timestamping");
  const validAt = (cert) => cert.notBefore <= time && time <= cert.notAfter;
  if (!validAt(signerCert)) return fail("certificate_not_valid_at_time");
  const issued = (cert, issuer) => cert.issuerRaw.equals(issuer.subjectRaw)
    && checkSignature(cert.signatureAlgorithm, null, cert.tbs, issuer.publicKey, cert.signature);
  let current = signerCert;
  let root = null;
  const used = new Set();
  for (let depth = 0; depth < MAX_CHAIN_DEPTH && !root; depth += 1) {
    root = trusted.find((candidate) => candidate.der.equals(current.der)) || trusted.find((candidate) => issued(current, candidate));
    if (root) break;
    const next = pool.find((candidate) => !used.has(candidate) && candidate !== current && candidate.isCa
      && candidate.keyUsage?.keyCertSign !== false && validAt(candidate) && issued(current, candidate));
    if (!next) break;
    used.add(next);
    current = next;
  }
  if (!root) return fail("chain_not_trusted");
  if (!validAt(root)) return fail("certificate_not_valid_at_time");

  return {
    valid: true,
    attested_time: time.toISOString(),
    serial: readIntegerHex(tstInfo, info[3]),
    policy_oid: readOid(tstInfo, info[1]),
    signer_common_name: signerCert.commonName,
    signer_organization: signerCert.organization,
    root_sha256: root.sha256,
    nonce,
  };
}

// ---------------------------------------------------------------------------------------
// A whole record: signature, content hash and every outside timestamp
// ---------------------------------------------------------------------------------------

export const CHECK_MEANING = Object.freeze({
  pageverified_signature: {
    proves: "PageVerified's key signed these exact record fields, so none of them has been changed since.",
    does_not_prove: "The time in the record is PageVerified's own clock. The signature does not show who wrote the page or that what the page says is true.",
  },
  content_hash: {
    proves: "A file with this SHA-256 is byte for byte the file the record describes.",
    does_not_prove: "It says nothing about what the live page shows now, or about who wrote it.",
  },
  outside_timestamp: {
    proves: "An authority that PageVerified does not run signed the SHA-256 of this exact record at the time shown. The record existed by then and has not been changed since.",
    does_not_prove: "The authority saw only a hash. It did not see the page, the URL or the file, and it does not vouch for them. This check does not look up whether the authority's certificate was later revoked.",
  },
});

// The one rule the server and this script both apply to an outside timestamp token.
//   roots       every root certificate to try (PEM text or DER), from all authorities at once:
//               the authority is identified by the root the chain ends at, never by a label
//               that came with the token.
//   knownRoots  { root sha256: authority name }. A token that chains to one of these passes
//               under that name.
//   anyRootPasses  true when every root in `roots` was chosen by the person checking (--roots):
//               a chain to any of them passes, named by knownRoots if listed.
// Returns { status: "pass" | "fail" | "unknown_authority", authority_name, outcome }.
// "unknown_authority" means the token could not be tied to a trusted root, so it was not
// checked; "fail" means it is broken or does not cover this record.
export const UNKNOWN_AUTHORITY = "Unknown authority";
export const SUPPLIED_ROOT_AUTHORITY = "The authority behind the root certificate you supplied";

export function judgeTimestamp(bytes, { digestHex, roots = [], knownRoots = KNOWN_ROOTS, anyRootPasses = false } = {}) {
  const outcome = digestHex ? verifyTimestampToken(bytes, { digestHex, roots }) : fail("record_unreadable");
  if (!outcome.valid) {
    const unknown = outcome.reason === "chain_not_trusted" || outcome.reason === "no_trusted_roots";
    return { status: unknown ? "unknown_authority" : "fail", authority_name: UNKNOWN_AUTHORITY, outcome };
  }
  const known = knownRoots[outcome.root_sha256];
  if (known) return { status: "pass", authority_name: known, outcome };
  if (anyRootPasses) return { status: "pass", authority_name: SUPPLIED_ROOT_AUTHORITY, outcome };
  return { status: "unknown_authority", authority_name: UNKNOWN_AUTHORITY, outcome };
}

// bundle: { record, signature, keys?, outside_timestamps?: [{ authority, name, token_base64,
//           root_certificates_pem }] }
// options.keys: a key set you trust (otherwise the one inside the bundle is used and said so).
// options.roots: root certificates you trust, as PEM text (otherwise the roots inside the bundle
//                are used, and only believed when their fingerprint is in KNOWN_ROOTS).
// options.fileSha256: SHA-256 of your copy of the captured file.
// options.knownRoots: { root sha256: name }, defaults to KNOWN_ROOTS.
// PVRF is self-contained here: this exact file is distributed as the offline CLI.
export const PVRF_TYPES = Object.freeze(['prepay_check', 'offer_receipt', 'purchase_receipt', 'snapshot', 'drift_event', 'listing_verification', 'readiness_report', 'allowlist_export', 'evidence_capture']);
const PVRF_FIELDS = ['pvrf', 'type', 'id', 'issuer', 'issued_at', 'subject', 'payload_sha256', 'payload_bytes', 'key_id', 'alg'];
export function jcs(value) {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${jcs(value[k])}`).join(',')}}`;
  throw new TypeError('payload_type_unsupported');
}
export function verifyPvrf(bundle, keys) {
  try {
    const e = bundle?.envelope;
    if (!e || typeof e !== 'object' || Array.isArray(e) || Object.keys(e).length !== PVRF_FIELDS.length || !PVRF_FIELDS.every(k => Object.hasOwn(e, k))) throw new Error('envelope_shape_invalid');
    if (e.pvrf !== '1' || !PVRF_TYPES.includes(e.type) || e.issuer !== 'pageverified.com' ||
        !['id', 'subject', 'key_id', 'issued_at'].every(k => typeof e[k] === 'string' && e[k].length > 0) ||
        e.subject.length > 2048 || !Number.isFinite(Date.parse(e.issued_at)) || new Date(e.issued_at).toISOString() !== e.issued_at ||
        !/^[0-9a-f]{64}$/.test(e.payload_sha256) || !Number.isSafeInteger(e.payload_bytes) || e.payload_bytes < 0 || e.payload_bytes > 262144) throw new Error('envelope_fields_invalid');
    const payload = Buffer.from(jcs(bundle.payload), 'utf8');
    const payloadValid = payload.length === e.payload_bytes && sha256Hex(payload) === e.payload_sha256;
    const jwk = (Array.isArray(keys?.keys) ? keys.keys : []).find(k => k?.kid === e.key_id);
    if (!jwk) return { valid: false, payloadValid, reason: 'unknown_key_id' };
    const alg = jwk.kty === 'OKP' && jwk.crv === 'Ed25519' ? 'EdDSA' : jwk.kty === 'EC' && jwk.crv === 'P-256' ? 'ES256' : null;
    if (!alg || alg !== e.alg || (jwk.alg && jwk.alg !== alg) || (jwk.use && jwk.use !== 'sig') ||
        typeof bundle.signature !== 'string' || !/^[A-Za-z0-9_-]{40,200}$/.test(bundle.signature)) throw new Error('signature_or_key_invalid');
    const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, ...(jwk.y ? { y: jwk.y } : {}) }, format: 'jwk' });
    const valid = cryptoVerify(alg === 'EdDSA' ? null : 'sha256', Buffer.from(canonicalize(e)),
      alg === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key, Buffer.from(bundle.signature, 'base64url'));
    return { valid, payloadValid, reason: valid ? null : 'signature_mismatch', key_id: e.key_id, alg, key_thumbprint: jwkThumbprint(jwk) };
  } catch (error) { return { valid: false, payloadValid: false, reason: error.message || 'record_invalid' }; }
}

export function verifyBundle(bundle, { keys = null, roots = null, fileSha256 = null, knownRoots = KNOWN_ROOTS } = {}) {
  const checks = [];
  const pvrf = bundle?.envelope && Object.hasOwn(bundle.envelope, 'pvrf');
  const record = pvrf ? bundle.envelope : bundle?.record;
  const signature = pvrf ? verifyPvrf(bundle, keys || bundle?.keys) : verifyRecordSignature({ record, signature: bundle?.signature }, keys || bundle?.keys);
  // A key that arrives inside the file being checked proves nothing by itself: whoever made the
  // file chose it. The signature counts as a pass only against a key set you supplied.
  checks.push({
    check: "pageverified_signature",
    result: !signature.valid ? "fail" : keys ? "pass" : "untrusted",
    detail: !signature.valid
      ? `The signature did not verify: ${signature.reason}.`
      : keys
        ? `Signed by key ${signature.key_id} (${signature.alg}), thumbprint ${signature.key_thumbprint}, from the key file you supplied.`
        : `The signature matches key ${signature.key_id} (${signature.alg}), thumbprint ${signature.key_thumbprint}, but that key came from inside this file, so this does not yet show PageVerified signed it. Download https://pageverified.com/.well-known/pageverified-keys.json yourself and run again with --keys.`,
    key_source: keys ? "supplied" : "bundle",
    ...CHECK_MEANING.pageverified_signature,
  });

  let digestHex = null;
  try { digestHex = recordDigestHex(record); } catch { /* reported by the signature check */ }

  if (pvrf) {
    checks.push({ check: 'payload_hash', result: signature.payloadValid ? 'pass' : 'fail',
      detail: signature.payloadValid ? 'The payload hash and canonical byte count match the signed envelope.' : 'The payload or its canonical byte count does not match the envelope.',
      proves: 'The supplied payload matches the hash recorded in the envelope.', does_not_prove: 'The observations in the payload are true or complete.' });
  } else if (fileSha256) {
    const same = typeof record?.sha256 === "string" && record.sha256 === String(fileSha256).toLowerCase();
    checks.push({
      check: "content_hash",
      result: same ? "pass" : "fail",
      detail: same ? `Your file's SHA-256 equals the hash in the record: ${record.sha256}.` : `Your file's SHA-256 is ${String(fileSha256).toLowerCase()}. The record says ${record?.sha256}. They are different files.`,
      ...CHECK_MEANING.content_hash,
    });
  } else {
    checks.push({
      check: "content_hash",
      result: "not_checked",
      detail: `No file was given. The record says the captured file has SHA-256 ${record?.sha256}. Run again with --file to compare your copy.`,
      ...CHECK_MEANING.content_hash,
    });
  }

  const timestamps = Array.isArray(bundle?.outside_timestamps) ? bundle.outside_timestamps : [];
  // Every root the file carries is tried for every token; the root the chain ends at names the
  // authority. A label in the file is never shown as a name.
  const bundleRoots = timestamps.flatMap((entry) => (Array.isArray(entry?.root_certificates_pem) ? entry.root_certificates_pem.map(String) : []));
  for (const entry of timestamps) {
    const token = Buffer.from(String(entry?.token_base64 || ""), "base64");
    const judged = judgeTimestamp(token, { digestHex, roots: roots ? [roots] : bundleRoots, knownRoots, anyRootPasses: Boolean(roots) });
    const { outcome } = judged;
    const result = judged.status === "pass" ? "pass" : judged.status === "fail" ? "fail" : "untrusted";
    checks.push({
      check: "outside_timestamp",
      // Only a built-in root gives an id. The file's own label is never repeated.
      authority: judged.status === "pass" ? KNOWN_ROOT_IDS[outcome.root_sha256] ?? null : null,
      authority_name: judged.authority_name,
      result,
      ...(outcome.valid ? { attested_time: outcome.attested_time, serial: outcome.serial, policy_oid: outcome.policy_oid, signer: outcome.signer_common_name, root_sha256: outcome.root_sha256 } : {}),
      detail: result === "fail"
        ? `This token did not verify: ${outcome.reason}.`
        : result === "pass"
          ? `${judged.authority_name} signed the hash of this record at ${outcome.attested_time}. Root certificate ${outcome.root_sha256}${roots ? " (from the roots file you supplied)" : ""}.`
          : outcome.valid
            ? `The token is signed and covers this record, but its root certificate ${outcome.root_sha256} is not one this script knows. Do not rely on it unless you can confirm that fingerprint with the authority and pass the root with --roots.`
            : "The token does not chain to any root certificate this script can use, so it was not checked.",
      ...CHECK_MEANING.outside_timestamp,
    });
  }

  const failed = checks.some((item) => item.result === "fail" || item.result === "untrusted");
  const stamped = checks.filter((item) => item.check === "outside_timestamp" && item.result === "pass");
  return {
    ok: !failed,
    verifier_version: VERIFIER_VERSION,
    record_sha256: digestHex,
    outside_timestamps_verified: stamped.length,
    earliest_attested_time: stamped.map((item) => item.attested_time).sort()[0] || null,
    checks,
    note: stamped.length
      ? "Revocation of the authorities' certificates is not checked. None of this is a legal certification."
      : "This record has no outside timestamp that verified, so its time rests on PageVerified's own clock and signature. None of this is a legal certification.",
  };
}

// ---------------------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------------------

function usage() {
  return [
    `pageverified-verify ${VERIFIER_VERSION}`,
    "",
    "Usage: node pageverified-verify.mjs <record.json> [options]",
    "",
    "  --file <path>    your copy of the captured file; its SHA-256 is compared with the record",
    "  --keys <path>    PageVerified's public key set (JWKS), downloaded by you from",
    "                   https://pageverified.com/.well-known/pageverified-keys.json",
    "  --roots <path>   root certificates you trust for the outside timestamps (PEM)",
    "  --export <dir>   write record.canonical.json, each token as .tsr and each root as .pem,",
    "                   and print the matching `openssl ts -verify` commands",
    "  --json           print the result as JSON",
    "",
    "Exit code 0: every check that ran passed. 1: a check failed or could not be trusted.",
    "2: the input could not be read.",
  ].join("\n");
}

function parseArguments(argv) {
  const options = { input: null, file: null, keys: null, roots: null, exportDir: null, json: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--json") options.json = true;
    else if (arg === "--file") options.file = argv[++index];
    else if (arg === "--keys") options.keys = argv[++index];
    else if (arg === "--roots") options.roots = argv[++index];
    else if (arg === "--export") options.exportDir = argv[++index];
    else if (arg === "--help" || arg === "-h") options.help = true;
    else if (!arg.startsWith("--") && !options.input) options.input = arg;
    else throw new Error(`unknown option: ${arg}`);
  }
  return options;
}

const safeName = (value, fallback) => String(value || fallback).toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "") || fallback;

function exportForOpenssl(bundle, dir) {
  mkdirSync(dir, { recursive: true });
  const lines = [];
  writeFileSync(path.join(dir, "record.canonical.json"), canonicalize(bundle.envelope || bundle.record));
  (bundle.outside_timestamps || []).forEach((entry, index) => {
    const name = safeName(entry.authority, `authority-${index + 1}`);
    writeFileSync(path.join(dir, `${name}.tsr`), Buffer.from(String(entry.token_base64 || ""), "base64"));
    writeFileSync(path.join(dir, `${name}-root.pem`), (entry.root_certificates_pem || []).join("\n"));
    lines.push(`openssl ts -verify -data record.canonical.json -in ${name}.tsr -CAfile ${name}-root.pem`);
  });
  return lines;
}

function main(argv) {
  let options;
  try {
    options = parseArguments(argv);
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}\n`);
    return 2;
  }
  if (options.help || !options.input) {
    process.stdout.write(`${usage()}\n`);
    return options.help ? 0 : 2;
  }
  let bundle;
  let report;
  try {
    bundle = JSON.parse(readFileSync(options.input, "utf8").replace(/^﻿/, ""));
    report = verifyBundle(bundle, {
      keys: options.keys ? JSON.parse(readFileSync(options.keys, "utf8").replace(/^﻿/, "")) : null,
      roots: options.roots ? readFileSync(options.roots, "utf8") : null,
      fileSha256: options.file ? sha256Hex(readFileSync(options.file)) : null,
    });
  } catch (error) {
    process.stderr.write(`Could not read the input: ${error.message}\n`);
    return 2;
  }
  const commands = options.exportDir && (bundle.record || bundle.envelope) ? exportForOpenssl(bundle, options.exportDir) : [];
  if (options.json) {
    process.stdout.write(`${JSON.stringify({ ...report, ...(commands.length ? { openssl: commands } : {}) }, null, 2)}\n`);
    return report.ok ? 0 : 1;
  }
  const mark = { pass: "PASS", fail: "FAIL", untrusted: "NOT TRUSTED", not_checked: "NOT CHECKED" };
  const title = { pageverified_signature: "PageVerified signature", content_hash: "Content hash", payload_hash: "Payload hash", outside_timestamp: "Outside timestamp" };
  const out = [`Record ${bundle.envelope?.id ?? bundle.record?.call_id ?? "(no id)"}`, `SHA-256 of the record: ${report.record_sha256 ?? "(unreadable)"}`, ""];
  for (const item of report.checks) {
    out.push(`[${mark[item.result]}] ${title[item.check]}${item.authority_name ? `: ${item.authority_name}` : ""}`);
    out.push(`    ${item.detail}`);
    out.push(`    Proves: ${item.proves}`);
    out.push(`    Does not prove: ${item.does_not_prove}`);
    out.push("");
  }
  if (!report.checks.some((item) => item.check === "outside_timestamp")) out.push("This record has no outside timestamp.", "");
  out.push(report.note);
  if (commands.length) out.push("", `Files written to ${options.exportDir}. To check the timestamps with OpenSSL, run there:`, ...commands.map((line) => `  ${line}`));
  const failedOutright = report.checks.some((item) => item.result === "fail");
  out.push("", report.ok ? "Result: every check that ran passed." : failedOutright ? "Result: at least one check FAILED." : "Result: NOT TRUSTED yet. Supply the missing keys or roots as described above.");
  process.stdout.write(`${out.join("\n")}\n`);
  return report.ok ? 0 : 1;
}

const runDirectly = (() => {
  try {
    return Boolean(process.argv?.[1]) && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
})();
if (runDirectly) process.exitCode = main(process.argv.slice(2));
