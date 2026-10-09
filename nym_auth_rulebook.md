---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frederic Nieto"
version: "0.1"
status: "public draft"
date: "2026-10-09"
---

# Introduction and Scope

## Scope

This document specifies the natural-person anonymous/pseudonymous authentication attestation** (`eu.europa.ec.eudi.nym_auth.1`). This attestation enables a Holder to:

1. Generate a pseudonyms with various properties for authentication, account binding, and known-offender matching.
2. Generate a zero-knowledge proof of correct pseudonym generation.
3. Prove zero-knowledge date-based predicates (e.g., age checks).

This version 0.1 targets circuit-based Zero-Knowledge Proof (ZKP) presentations using the `circuit_zk` presentation format over an ISO/IEC 18013-5 compliant attestation. The following are out of scope:

* Non-circuit ZKPs (like BBS and other zero-knowledge signature formats).
* Non-ZKP fallbacks.
* SD-JWT VC encodings.
* Revocation and validity checks. The circuit checks these using a mandated mechanism.

Pseudonyms, ZKP proof systems referenced herein, and circuit definitions are defined externally in:

* Source for pseudonym spec.
* Source for proof systems.
* Source for circuit definitions.

Approved circuit verification hashes and parameter mappings are maintained in a registry of approved circuits.

## System Roles

* **Issuer:** Issues a signed attestation with attributes and statements about an identity subject.
* **Circuit provider:** Issues a signed circuit suitable for a specified presentation request.
* **Prover (Holder, Wallet Unit):** Stores the issuer-signed attestation, generates pseudonyms, and produces ZKP.
* **Verifier (Relying Party):** Requests at least one function execution and/or a claim via DCQL and validates the ZKP.

## Key Words

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

---

# Attestation Data Model and Attributes

## Attribute Overview

| Data Identifier | Attribute Identifier | CBOR / CDDL Representation | Presence | Description |
| :--- | :--- | :--- | :--- | :--- |
| **birth_date** | `birth_date` | `#6.1004(tstr)` (`full-date`) | REQ | Day, month, and year of birth. Used as input for zero-knowledge date comparison predicates. |
| **secret_seed_commitment** | `ssc` | `bstr` (32 bytes) | REQ | **Issuer Known Seed Commitment**: $`C = \text{SHA-256}(\text{secret\_seed})`$ where $`\text{secret\_seed}`$ is a 16-byte random shared secret between the issuer and prover. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | OPT | **Issuer Unknown Seed Commitment**: $`C = \text{SHA-256}(\text{private\_seed})`$ where $`\text{private\_seed}`$ is a 16-byte random value known only to the prover. |

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

The complete attribute map for the `eu.europa.ec.eudi.nym_auth.1` namespace MUST conform to the following CDDL specification (RFC 8610):

```cddl
nym_auth_namespace = {
  "birth_date" => full_date,
  "ssc"       => ssc_type,
  ? "psc"     => psc_type
}

full_date = #6.1004(tstr)
ssc_type = bstr .size 32
psc_type = bstr .size 32
```

The map and all contained data items MUST be encoded according to RFC 8949, Section 4.2.1 (Core Deterministic Encoding Requirements). The `birth_date` value MUST be a CBOR tag 1004 text string conforming to RFC 8943, containing a valid RFC 3339 `full-date`.

# DCQL Profile and Presentation Syntax (`circuit_zk`)

## Overview and fail-closed design

This profile extends OpenID4VP Digital Credentials Query Language (DCQL) for zero-knowledge circuit presentations. 

A Wallet Unit that does not support the format `circuit_zk` cannot satisfy the Credential Query and MUST NOT return any. For `"format": "circuit_zk"`, issuer-signed attributes are never disclosed directly. All calculations and assertions MUST be requested inside `req`.

A Wallet Unit MUST treat an option as unsatisfiable if it encounters an unknown function `id`, undeclared or invalid `parameters`, if no approved circuit is available for the requested combination of statement, or if the circuit does not support the request function or parameters. If an option is unsatisfiable, the wallet unit MUST reply with an Error Response as defined in OID4VP 1.0 [Section 8.5](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-error-response).

## Query structure

A Credential Query targeting `"eu.europa.ec.eudi.nym_auth.1"` MUST observe the following rules:

* `format` (REQUIRED): MUST be set to `"circuit_zk"`
* `meta` (REQUIRED): MUST contain doctype_value set to `"eu.europa.ec.eudi.nym_auth.1"`.
* `req` (REQUIRED): A non-empty array of objects specifying proven zero-knowledge calculations and predicates.

> **NOTE**: Proof system capability negotiation (e.g., supported ZK proof systems) occurs at the protocol level as defined in Sections 10-11 in OID4VP 1.0.

### `req` item member specification

Each object inside the `req` array MUST contain:

| Member | Type | Presence | Description |
| :--- | :--- | :--- | :--- |
| `id` | String | REQ | Function Type Identifier registered in Section 5 (e.g., `"pseudonym-v1-sha256"`, `"age_check"`). |
| `return` | String | REQ | An output handle unique within the Credential Query for mapping the result into `public_outputs.results`. |
| `params` | Object | OPT | Key-value mapping of declared parameters for the specified function. Omission applies the function's defined defaults. | 

## Response processing and results mapping

The Wallet Unit generates a proof using a circuit covering all requested statements in `req` in a single proof bound to the presentation `SessionTranscript`.

> **NOTE:** It is possible to use two distinct attestations, one for age and one for pseudonym, but if both require 2FA the user experience is degraded. In this version, both age verification and pseudonym is satisfied using a single attestation `nym_auth`.

In the returned `vp_token`, computed outputs MUST be placed in a top-level CBOR map named `results` inside `public_outputs`. The `results` map keys MUST match the corresponding `return` handle of each item in `req`.

```json
"public_outputs": {
  "results": {
    "nym-123": "<32-byte base64url string>",
    "age-range-123": true
  }
}
```

## Example DCQL request

Illustrative only. The example below will be updated to align with the OpenID drafts.

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
      "circuit_zk": {
        "circuit_proof_system_values": [
          "longfellow-libzk-v1"
        ],
        "circuit_id_values": [
          "urn:circuits:longfellow:nym_auth:v1"
        ]
      }
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
              "config": "known-offender-matching-ssc"
            }
          },
          {
            "id": "age_check",
            "return": "age-range-123",
            "params": {
              "gt": "2008-10-09",
              "le": "2013-10-09"
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

## Pseudonym generation function (`pseudonym-v1-sha256`)

Derives a deterministic pseudonym using the SHA-256 instantiation defined in [ETSI SOURCE]().

* Function identifier (`id`): `"pseudonym-v1-sha256"`.
* Source attribute: `ssc` (or `psc` when configured). Note that the generation does not use `ssc` or `psc` directly, but their openings (`secret_seed` and `private_seed`).
* Output: A 32-byte base64url-encoded string placed in `results[<handle>]`.

### Parameters

This specification version enables the following function parameters.

| Parameter | Type | Presence | Description | Parameter restrictions | 
| :-- | :-- | :-- | :-- | :-- |
| `config` | string | REQ | Identifier for standard configurations. | Allowed values are specified in the configurations below. |
| `verifier_context` | string | CON | Additional context supplied by the verifier. | Presence as required by the selected configuration. UTF-8, 1–64 bytes. |

A Wallet Unit MUST treat the request as unsatisfiable if `verifier_context` is absent for a configuration that requires it, present for a configuration that does not allow it, or longer than 64 bytes.

### Configurations

All configurations generate the pseudonym as: `pseudonym = SHA256(DST || {secret, private}_seed || prover_input || verifier_input)`. The `attribute_source` determines which seed to use. The `DST` is set to `nym_auth/v1/<config>`. The verifier MUST recompute and supply its own public inputs to the circuit proof verification.

#### `known-offender-matching-ssc`

The `known-offender-matching-ssc` configuration is defined in [ETSI SOURCE]() as follows:

1. `attribute_source` is the `ssc` (issuer known seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(secret_seed) == ssc`; generation uses `secret_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is set to the end relying party unique identifier (cf [Topic X](https://eudi.dev/latest/discussion-topics/x-relying-party-registration/#35-registration-certificate-for-intermediaries)), which consists of the `x509_san_dns:` prefix followed by the fully qualified domain name of the verifier bound to its X.509 Access Certificate, e.g., `"x509_san_dns:rp.example.com"`. Thus `verifier_input` is the output of the SHA256 digest of the UTF-8 encoding of `"x509_san_dns:rp.example.com"`.

When the Verifier is an intermediary, the Wallet Unit MUST NOT use the intermediary `client_id` and MUST use the end Relying Party identifier. If the end Relying Party identifier cannot be ascertained, the Wallet Unit MUST not present a pseudonym.

The configuration properties are as follows:

* The pseudonym value is distinct per `client_id`.
* The pseudonym can be remapped to an identity by the issuer, who knows the `secret_seed` value.
* It supports known offender matching.

> **NOTE 1**: If the issuer known seed changes, so does the pseudonym generated. A ban can be evaded by changing the issuer to one using a different issuer known seed.
> **NOTE 2**: If the `verifier_input` changes, so does the pseudonym generated. Known offender matching is not possible if the Verifier identity changes.

#### `known-offender-matching-psc`

1. `attribute_source` is the `psc` (issuer unknown seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(private_seed) == psc`; generation uses `private_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is set to the end relying party unique identifier (cf [Topic X](https://eudi.dev/latest/discussion-topics/x-relying-party-registration/#35-registration-certificate-for-intermediaries)), which consists of the `x509_san_dns:` prefix followed by the fully qualified domain name of the verifier bound to its X.509 Access Certificate, e.g., `"x509_san_dns:rp.example.com"`. Thus `verifier_input` is the output of the SHA256 digest of the UTF-8 encoding of `"x509_san_dns:rp.example.com"`.

When the Verifier is an intermediary, the Wallet Unit MUST NOT use the intermediary `client_id` and MUST use the end Relying Party identifier. If the end Relying Party identifier cannot be ascertained, the Wallet Unit MUST not present a pseudonym.

The configuration properties are as follow:

* The pseudonym value is distinct per `client_id`.
* Remapping the pseudonym to an identity is as hard as brute forcing the `private_seed`, which is intractable.
* To supports known offender matching, the issuer MUST only allow one `psc` per identity subject.

> **NOTE 1**: If the issuer changes, it may allow a new `psc`, which changes the pseudonym generated.
> **NOTE 2**: If the `verifier_input` changes, so does the pseudonym generated. Known offender matching is not possible if the Verifier identity changes.

#### `account-recovery-ssc`

1. `attribute_source` is the `ssc` (issuer known seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(secret_seed) == ssc`; generation uses `secret_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` takes both the end relying party unique identifier (cf [Topic X](https://eudi.dev/latest/discussion-topics/x-relying-party-registration/#35-registration-certificate-for-intermediaries)), which consists of the `x509_san_dns:` prefix followed by the fully qualified domain name of the verifier bound to its X.509 Access Certificate, e.g., the UTF-8 encoding of `"x509_san_dns:rp.example.com"`; and additional UTF-8 encoded `verifier_context` as supplied by the verifier. The resulting `verifier_input` is the SHA256 digest of the two values' respective SHA256 digests concatenated: `SHA256(SHA256(verifier_id) || SHA256(verifier_context))`.

Properties:

* The pseudonym value is distinct per `client_id + verifier_context`.
* The pseudonym can be remapped to an identity by the issuer, who knows the `secret_seed` value.
* Supports account recovery for a given account as identified by the `verifier_context`.
* Supports known offender matching per supplied `verifier_context`.

#### `user-managed-pseudonym-xsite-ssc`

1. `attribute_source` is the `ssc` (issuer known seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(secret_seed) == ssc`; generation uses `secret_seed`.
2. `prover_input` is the SHA256 digest of a user-supplied value; shared across the sites the user wants to be linked across.
3. `verifier_input` is null (32 zero bytes).

Properties:

* The same pseudonym value can be presented to different verifiers.
* Remapping the pseudonym to an identity is as hard as brute forcing the `prover_input`.
* Does not offer sybil resistance.
* Does not support known offender matching.

## Date predicate function (`age_check`)

Zero-knowledge comparison operators operating strictly over the `birth_date` attribute (`#6.1004(tstr)`). Used to prove age thresholds, or ranges.

> **NOTE:** Date predicates in this version does not support exact date matches. Because an range can be used to get exact date match restrictions on the interval between the lower and upper bound are needed. These restrictions are use case specific.

* Function identifier (`id`): `"age_check"`.
* Source attribute: `birth_date`.
* Output: The assertion result placed in `results[<handle>]`.

### Parameters

| Parameter | Type   | Presence | Description |
|-----------|--------|----------|-------------|
| `gt`      | String | OPT | Born strictly after date: $`\text{birth\_date} \gt \text{date}`$. |
| `ge`      | String | OPT | Born on or after date: $`\text{birth\_date} \ge \text{date}`$. |
| `lt`      | String | OPT | Born strictly before date: $`\text{birth\_date} \lt \text{date}`$. |
| `le`      | String | OPT | Born on or before date: $`\text{birth\_date} \le \text{date}`$. |

At least one parameter MUST be present. Multiple bounds can be combined in a single `age_check` call to prove an age range in one statement.

A wallet unit MUST reject any request that specifies both a lower bound (`gt` or `ge`) and an upper bound (`lt` or `le`) when the interval between the specified dates is less than one calendar year. This applies to the intersection of all date predicates in one `req`.

# Presentation

## Approved circuits

The ecosystem maintains a registry of approved circuits. Given the attestation type (`eu.europa.ec.eudi.nym_auth.1`), presentation format (`circuit_zk`), and the requested functions in `req`, the Wallet Unit and Verifier look up an approved circuit from the registry. Each circuit MUST have a unique identifier.

## Presentation flow initiation

When the Authorization Request uses `request_uri_method=post`, the Wallet Unit MAY send capability information in `wallet_metadata`, and the Verifier SHOULD tailor the Request Object to them.

Correspondingly, for a verifier-initiated flow, the verifier can announce its capabilities inside `client_metadata.vp_formats_supported` and list supported proof systems (e.g., `circuit_proof_system_values: ["longfellow-libzk-v1", "vega-v2", ...]`), and circuit identifiers (e.g., `circuit_id_values: ["urn:circuits:longfellow:nym_auth:v1", "urn:circuits:vega:nym_auth:v5"]]`).

## The `circuit_zk` format

The following parameters MAY be used in the `circuit_zk` object of `vp_formats_supported`, in Verifier metadata (`client_metadata`) and in Wallet
metadata (`wallet_metadata`):

* `circuit_proof_system_values`: OPTIONAL. Non-empty array of proof system identifiers from the approved circuit registry.
* `circuit_id_values`: OPTIONAL. Non-empty array of unique circuit identifiers from the approved circuit registry.

When the Verifier provides these parameters, the Wallet Unit MUST select an approved circuit whose proof system and identifier are both listed and which supports every item in `req`; if none exists, the request is unsatisfiable. The presentation response MUST identify the circuit identifier used.

## Binding

A `circuit_zk` presentation MUST be bound to the presentation session. The circuit MUST verify, as a private computation, the device signature over the ISO/IEC 18013-5 `DeviceAuthentication` structure, which contains the `SessionTranscript`.

The `SessionTranscript` is `[null, null, Handover]`, with `Handover` constructed as defined in OpenID4VP 1.0 Appendix B.2.6.

Over DC API the following applies to bind the pseudonym to the Verifier:

1. Requests for `eu.europa.ec.eudi.nym_auth.1` sent over the Digital Credentials API MUST use the `openid4vp-v1-signed` protocol. An unsigned request MUST be rejected.
2. The Wallet Unit MUST validate the Request Object signature and certificate chain according to the Client Identifier Prefix and, over the Digital Credentials API, MUST verify that the calling origin is contained in `expected_origins`.

