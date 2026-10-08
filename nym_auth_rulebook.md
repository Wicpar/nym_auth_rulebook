---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frederic Nieto"
version: "0.1"
status: "public draft"
date: "2026-10-08"
---

# Introduction and Scope

## Scope

This document specifies the natural-person anonymous/pseudonymous authentication attestation** (`eu.europa.ec.eudi.nym_auth.1`). This attestation enables a Holder to:

1. Generate a pseudonyms with various properties for authentication, account binding, and known-offender matching.
2. Generate a zero-knowledge proof of correct pseudonym generation.
3. Prove zero-knowledge date-based predicates (e.g., age checks).

This version 0.1 targets circuit-based Zero-Knowledge Proof (ZKP) presentations using the `circuit_zk` presentation format over a ISO/IEC 18013-5 compliant attestation. The following are out of scope:

* Non-circuit ZKPs (like BBS and other zero-knowledge signature formats).
* Non-ZKP fallbacks.
* SD-JWT VC encodings.

Mathematical derivations of pseudonyms, ZKP proof systems referenced herein, and circuit definitions are defined externally in:

* Source for pseudonym spec. Implementations MUST align with that specification.
* Source for proof systems.
* Source for circuit definitions.

Approved circuit verification hashes and parameter mappings are maintained in a registry of approved circuits.

## System Roles

* **Issuer:** Issues a signed attestation with attributes and statements about an identity subject.
* **Circuit provider:** Issues a signed circuit suitable for a specified presentation request.
* **Prover:** Stores the issuer-signed attestation, generates pseudonyms, and produces ZKP. Can initiate the presentation flow.
* **Verifier (Relying Party):** Requests at least one function execution and/or a claim via DCQL and validates the ZKP. Can initiate the presentation flow.

## Key Words

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

---

# Attestation Data Model and Attributes

## Attribute Overview

| Data Identifier | Attribute Identifier | CBOR / CDDL Representation | Presence | Description |
| :--- | :--- | :--- | :--- | :--- |
| **birth_date** | `birth_date` | `#6.1004(tstr)` (`full-date`) | **M** | Day, month, and year of birth[cite: 5]. Used as input for zero-knowledge date comparison predicates. |
| **secret_seed_commitment** | `ssc` | `bstr` (32 bytes) | **M** | **Issuer Known Seed Commitment**: $`C = \text{SHA-256}(\text{secret\_seed})`$ where $`\text{secret\_seed}`$ is a 16-byte random shared secret between the issuer and prover. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | **O** | **Issuer Unknown Seed Commitment**: $`C = \text{SHA-256}(\text{private\_seed})`$ where $`\text{private\_seed}`$ is a 16-byte random value known only to the prover. |

> **NOTE**: Issuer identity and attestation authenticity are established exclusively through the Mobile Security Object (MSO) signature and its associated X.509 certificate chain.

Furthermore:

* Validity information with `validityInfo` MUST be `signed` and include `"validFrom"` and `"validUntil"`.
* The attestation MUST be cryptographically bound to a hardware protected signing key detailed in `"deviceKeyInfo.deviceKey"`.
* The digests MUST be generated using `"digestAlgorithm": "SHA-256"`.
* The issuer signing key MUST exist in a certificate in an `x5chain` of `issuerAuth`.

---

# ISO/IEC 18013-5 Compliant Encoding

## Document type and Namespace

For attestations complying with ISO/IEC 18013-5, the Document Type (`docType`) and Namespace MUST both be set to: `eu.europa.ec.eudi.nym_auth.1`

## Attribute encodings and CDDL specification

All data elements in the `eu.europa.ec.eudi.nym_auth.1` namespace MUST be encoded as canonical CBOR (RFC 8949) according to the Concise Data Definition Language (CDDL; RFC 8610) specification below.

```cddl
nym_auth_namespace = {
  "birth_date" => full_date,
  "iksc"       => iksc_type,
  ? "iusc"     => iusc_type
}

full_date = #6.1004(tstr) ; RFC 8943 tag 1004, YYYY-MM-DD string
iksc_type = bstr .size 32  ; 32-byte SHA-256 commitment to 16-byte issuer-known seed
iusc_type = bstr .size 32  ; 32-byte SHA-256 commitment to 16-byte issuer-unknown seed
```

# DCQL Profile and Presentation Syntax (`circuit_zk`)

## Overview and fail-closed design

This profile extends OpenID4VP Digital Credentials Query Language (DCQL) for zero-knowledge circuit presentations. 

A Wallet Unit that does not support the format `circuit_zk` cannot satisfy the Credential Query and MUST NOT return any. For `"format": "circuit_zk"`, issuer-signed attributes are never disclosed directly. All calculations and assertions MUST be requested inside `req`.

A Wallet Unit MUST treat an option as unsatisfiable if it encounters an unknown function `id`, undeclared or invalid `parameters`, if no approved circuit is available for the requested combination of statement, or if the circuit does not support the request function or parameters. If an option is unsatisfiable, the wallet unit MUST reply with an Error Response as defined in OID4VCI 1.0 [Section 8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response).

## Query structure

A Credential Query targeting `"eu.europa.ec.eudi.nym_auth.1"` MUST observe the following rules:

* `format` (REQUIRED): MUST be set to `"circuit_zk"`
* `meta` (REQUIRED): MUST contain doctype_value set to `"eu.europa.ec.eudi.nym_auth.1"`.
* `req` (REQUIRED): A non-empty array of objects specifying proven zero-knowledge calculations and predicates.

> **NOTE**: Proof system capability negotiation (e.g., supported ZK proof systems) occurs at the protocol level as defined in Sections 10-11 in OID4VCI 1.0.

### `req` item member specification

Each object inside the `req` array MUST contain:

| Member | Type | Presence | Description |
| :--- | :--- | :--- | :--- |
| `id` | String | M | Function Type Identifier registered in Section 5 (e.g., `"pseudonym-v1-sha256"`, `"age_check"`). |
| `return` | String | O | A presentation-unique output handle for mapping the result into `public_outputs.results`. |
| `params` | Object | O | Key-value mapping of declared parameters for the specified function. Omission applies the function's defined defaults. | 

## Response procession and results mapping

The Wallet Unit generates a proof using a circuit covering all requested statements in `req` in a single proof bound to the presentation `SessionTranscript`.

> **NOTE:** It is possible to use two distinct attestations, one for age and one for pseudonym, but if both require 2FA the user experience is degraded.

In the returned `vp_token`, computed outputs MUST be placed in a top-level CBOR map named `results` inside `public_outputs`. The `results` map keys MUST match the corresponding `return` handle of each item in `req`.

```json
"public_outputs": {
  "results": {
    "nym-123": "<32-byte base64url string>",
    "age_check": true
  }
}
```

## Example DCQL request

```json
{
  "response_type": "vp_token",
  "response_mode": "dc_api.jwt",
  "nonce": "n-0S6_WzA2Mj",
  "client_id": "x509_san_dns:rp.example.com",
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
          "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
          "use": "enc",
          "alg": "ECDH-ES",
          "kid": "1"
        }
      ]
    },
    "vp_formats_supported": {
      "circuit_zk": {}
    }
  },
  "dcql_query": {
    "credentials": [
      {
        "id": "nym_attestation",
        "format": "circuit_zk",
        "meta": {
          "doctype_value": "eu.europa.ec.eudi.nym_auth.1"
        },
        "req": [
          {
            "id": "pseudonym-v1-sha256",
            "return": "nym-123",
            "params": {
              "config": "known-offender-matching"
            }
          },
          {
            "id": "age_check",
            "params": {
              "gt": "2008-10-07",
              "lte": "2013-10-07"
            }
          }
        ]
      }
    ]
  }
}
```

# Function catalogue

Functions invoked inside req MUST be registered in this specification or an official extension profile. Each registered function defines:

1. The mathematical operation, possible intermediate values, and parameter constraints.
2. The implicit credential source attribute(s) bound to the computation.
3. The expected output representation in the presentation response `results` map.

If a Wallet Unit receives a request for a function `id` not defined below or not listed in an approved circuit for the `doctype_value`, the affected option MUST be treated as unsatisfiable.
