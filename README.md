# ga4gh-visa-issuer

A small GA4GH Visa issuer and a Passport Clearinghouse check, written as a **test fixture** for trying the
[GA4GH Passport](https://github.com/ga4gh/aai/blob/master/AAI/ga4gh_passport_v1.md) flow with public-key signatures.
It is not a production service: it has no authentication, and its signing key is generated at start-up.

Why it exists: the GA4GH Starter Kit Passport Broker signs Visas with HMAC256 (a shared secret), and
`keycloak-ga4gh-visa-issuer` does not issue `ControlledAccessGrants` Visas. Neither lets a clearinghouse verify a
`ControlledAccessGrants` Visa with the issuer's public key. This project does.

## What it does

- Signs `ControlledAccessGrants` Visas as ES256 JSON Web Tokens (EC P-256). The JWS header carries `alg`, `kid`
  (RFC 7638 thumbprint), `typ` (`vnd.ga4gh.visa+jwt`) and `jku`.
- Publishes the public key as a JSON Web Key Set.
- Verifies Visas like a Passport Clearinghouse: it fetches the key set of a trusted issuer over HTTP and checks the
  signature (JDK `Signature`, independent of the library that signs), `exp`, `type`, the dataset URL (`value`, compared
  as a case-sensitive string), `by`, `source`, and the absence of `conditions`. `alg` other than ES256 (including `none`
  and HS256) is rejected before any key is looked up.

## Endpoints

| Endpoint | Meaning |
|---|---|
| `GET /.well-known/jwks.json` | the public key (JSON Web Key Set) |
| `GET /passport/{sub}` | `{"ga4gh_passport_v1": [<Visa JWT>, ...]}`, one Visa per grant of `sub` |
| `GET /grants`, `PUT /grants` | the grants that are signed now; `PUT` replaces all of them (a JSON array), so a test can give and take away a grant |
| `POST /verify` | body `{"passport": [<Visa JWT>, ...], "expectedValue": "<dataset URL>"}`; returns `{"granted": true/false, "reason": "..."}` |

## Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `VISA_ISSUER_URL` | `http://localhost:8080` | the `iss` of every Visa and the base of `jku`; verifiers must be able to reach it |
| `VISA_LIFETIME_SECONDS` | `3600` | lifetime of a Visa |
| `VISA_GRANTS_FILE` | (none) | path of the grants JSON file |
| `VISA_JWKS_URI` | `http://localhost:8080/.well-known/jwks.json` | where `/verify` fetches the key set of the trusted issuer |
| `VISA_TRUSTED_SOURCES` | (any) | comma-separated `source` values that `/verify` trusts |

`/verify` trusts one issuer (`VISA_ISSUER_URL`) and accepts Visas whose `by` is `dac`.

The grants file is a JSON array:

```json
[
  {"sub": "researcher-0001", "value": "https://example.org/datasets/JGAD000001",
   "source": "https://example.org/committees/0001", "by": "dac", "asserted": 1792886400}
]
```

## Build and test

```bash
rm -rf target
mvn test        # 14 unit tests; no Quarkus start, no network
mvn package     # fast-jar in target/quarkus-app
java -jar target/quarkus-app/quarkus-run.jar
```

Requires JDK 25 and Maven. The unit tests are plain JUnit; they sign Visas, tamper with them, and check that the
verifier rejects a changed payload, an expired Visa, an untrusted issuer, another dataset, an unaccepted authority,
and symmetric or `none` algorithms.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
