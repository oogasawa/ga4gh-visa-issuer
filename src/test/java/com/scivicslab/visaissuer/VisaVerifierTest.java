package com.scivicslab.visaissuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Unit tests of the Visa signer and verifier. No Quarkus, no network. */
class VisaVerifierTest {

    private static final String ISSUER = "https://issuer.example.org";
    private static final String DATASET = "https://example.org/datasets/JGAD000001";
    private static final String COMMITTEE = "https://example.org/committees/0001";
    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private SigningKey key;
    private VisaSigner signer;
    private Clock clock;

    @BeforeEach
    void setUp() {
        key = SigningKey.generate();
        clock = Clock.fixed(NOW, ZoneOffset.UTC);
        signer = new VisaSigner(key, ISSUER, 3600, clock);
    }

    private Grant grant(String by) {
        return new Grant("researcher-0001", DATASET, COMMITTEE, by, NOW.getEpochSecond() - 86400);
    }

    private VisaVerifier verifier(SigningKey served, Clock verifierClock) {
        return new VisaVerifier(Map.of(ISSUER, ISSUER + "/.well-known/jwks.json"), Set.of("dac"), Set.of(COMMITTEE),
                uri -> JSON.writeValueAsString(served.jwks()), verifierClock);
    }

    private static Map<String, Object> segment(String jwt, int index) throws Exception {
        return JSON.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[index]), new com.fasterxml.jackson.core.type.TypeReference<>() {
        });
    }

    @Test
    void acceptsAVisaSignedByTheTrustedIssuer() {
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(signer.sign(grant("dac")), DATASET);
        assertTrue(result.granted(), result.reason());
    }

    @Test
    void theVisaHeaderCarriesAlgTypKidAndJku() throws Exception {
        Map<String, Object> header = segment(signer.sign(grant("dac")), 0);
        assertEquals("ES256", header.get("alg"));
        assertEquals("vnd.ga4gh.visa+jwt", header.get("typ"));
        assertEquals(key.keyId(), header.get("kid"));
        assertEquals(ISSUER + "/.well-known/jwks.json", header.get("jku"));
    }

    @Test
    void rejectsAVisaWhosePayloadWasChangedAfterSigning() throws Exception {
        String jwt = signer.sign(grant("dac"));
        String[] parts = jwt.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8)
                .replace("JGAD000001", "JGAD000002");
        String forged = parts[0] + "." + B64URL.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(forged, "https://example.org/datasets/JGAD000002");
        assertFalse(result.granted());
        assertTrue(result.reason().contains("signature"), result.reason());
    }

    @Test
    void rejectsAVisaWhoseKidIsNotInTheFetchedKeySet() throws Exception {
        SigningKey other = SigningKey.generate();
        // The verifier fetches the key set of "other", which has no key with the kid of "key".
        String jwt = signer.sign(grant("dac"));
        VisaVerifier.Result result = verifier(other, clock).verifyVisa(jwt, DATASET);
        assertFalse(result.granted());
    }

    @Test
    void rejectsAnExpiredVisa() {
        Clock later = Clock.fixed(NOW.plusSeconds(3601), ZoneOffset.UTC);
        VisaVerifier.Result result = verifier(key, later).verifyVisa(signer.sign(grant("dac")), DATASET);
        assertFalse(result.granted());
        assertTrue(result.reason().contains("expired"), result.reason());
    }

    @Test
    void rejectsAnUntrustedIssuer() {
        VisaSigner stranger = new VisaSigner(key, "https://stranger.example.org", 3600, clock);
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(stranger.sign(grant("dac")), DATASET);
        assertFalse(result.granted());
        assertTrue(result.reason().contains("not trusted"), result.reason());
    }

    @Test
    void rejectsADifferentDataset() {
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(signer.sign(grant("dac")),
                "https://example.org/datasets/JGAD000002");
        assertFalse(result.granted());
    }

    @Test
    void comparesTheValueCaseSensitively() {
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(signer.sign(grant("dac")), DATASET.toLowerCase());
        assertFalse(result.granted());
    }

    @Test
    void rejectsAnAuthorityThePolicyDoesNotAccept() {
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(signer.sign(grant("self")), DATASET);
        assertFalse(result.granted());
        assertTrue(result.reason().contains("authority"), result.reason());
    }

    @Test
    void rejectsAnUntrustedSource() {
        Grant other = new Grant("researcher-0001", DATASET, "https://example.org/committees/9999", "dac", 1);
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(signer.sign(other), DATASET);
        assertFalse(result.granted());
        assertTrue(result.reason().contains("source"), result.reason());
    }

    @Test
    void rejectsAVisaSignedWithASymmetricAlgorithm() throws Exception {
        // A header that claims HS256 must be rejected before any key is looked up.
        String header = B64URL.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64URL.encodeToString(("{\"iss\":\"" + ISSUER + "\",\"exp\":9999999999}").getBytes(StandardCharsets.UTF_8));
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(header + "." + payload + ".AAAA", DATASET);
        assertFalse(result.granted());
        assertTrue(result.reason().contains("alg"), result.reason());
    }

    @Test
    void rejectsAVisaWithAlgNone() {
        String header = B64URL.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = B64URL.encodeToString("{}".getBytes(StandardCharsets.UTF_8));
        VisaVerifier.Result result = verifier(key, clock).verifyVisa(header + "." + payload + ".", DATASET);
        assertFalse(result.granted());
    }

    @Test
    void aPassportIsGrantedWhenAnyVisaIsAccepted() {
        String forged = signer.sign(grant("self"));
        String good = signer.sign(grant("dac"));
        assertTrue(verifier(key, clock).verifyPassport(List.of(forged, good), DATASET).granted());
        assertFalse(verifier(key, clock).verifyPassport(List.of(forged), DATASET).granted());
        assertFalse(verifier(key, clock).verifyPassport(List.of(), DATASET).granted());
    }

    @Test
    void theJwkThumbprintIsTheKeyId() throws Exception {
        Map<String, Object> jwk = key.jwk();
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + jwk.get("x") + "\",\"y\":\"" + jwk.get("y") + "\"}";
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        assertEquals(B64URL.encodeToString(digest), jwk.get("kid"));
        assertEquals(43, ((String) jwk.get("x")).length());
    }
}
