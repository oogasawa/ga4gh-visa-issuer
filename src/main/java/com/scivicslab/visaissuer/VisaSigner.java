package com.scivicslab.visaissuer;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.build.Jwt;

/** Builds and signs ControlledAccessGrants Visas as ES256 JSON Web Tokens. */
public final class VisaSigner {

    private final SigningKey key;
    private final String issuer;
    private final long lifetimeSeconds;
    private final Clock clock;

    public VisaSigner(SigningKey key, String issuer, long lifetimeSeconds, Clock clock) {
        this.key = key;
        this.issuer = issuer;
        this.lifetimeSeconds = lifetimeSeconds;
        this.clock = clock;
    }

    /** The URL where a verifier fetches the public key; it is put in the JWS header as jku. */
    public String jwksUri() {
        return issuer + "/.well-known/jwks.json";
    }

    public String sign(Grant grant) {
        long now = clock.instant().getEpochSecond();
        Map<String, Object> visa = new LinkedHashMap<>();
        visa.put("type", "ControlledAccessGrants");
        visa.put("asserted", grant.asserted());
        visa.put("value", grant.value());
        visa.put("source", grant.source());
        visa.put("by", grant.by());
        return Jwt.claims()
                .issuer(issuer)
                .subject(grant.sub())
                .issuedAt(now)
                .expiresAt(now + lifetimeSeconds)
                .claim("ga4gh_visa_v1", visa)
                .jws()
                .algorithm(SignatureAlgorithm.ES256)
                .keyId(key.keyId())
                .type("vnd.ga4gh.visa+jwt")
                .header("jku", jwksUri())
                .sign(key.privateKey());
    }
}
