package com.scivicslab.visaissuer;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The EC P-256 key pair that signs the Visas, with its key identifier and its JSON Web Key.
 * The key pair is generated when the process starts, so the public key changes after a restart.
 */
public final class SigningKey {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final KeyPair keyPair;
    private final String keyId;
    private final String x;
    private final String y;

    private SigningKey(KeyPair keyPair) throws Exception {
        this.keyPair = keyPair;
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        this.x = B64URL.encodeToString(unsigned32(publicKey.getW().getAffineX()));
        this.y = B64URL.encodeToString(unsigned32(publicKey.getW().getAffineY()));
        // RFC 7638 JWK thumbprint: the required members in lexicographic order, no whitespace.
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}";
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
        this.keyId = B64URL.encodeToString(digest);
    }

    public static SigningKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return new SigningKey(generator.generateKeyPair());
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate the EC P-256 signing key", e);
        }
    }

    public String keyId() {
        return keyId;
    }

    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    /** The public key as a JSON Web Key (RFC 7517). */
    public Map<String, Object> jwk() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", x);
        jwk.put("y", y);
        jwk.put("kid", keyId);
        jwk.put("use", "sig");
        jwk.put("alg", "ES256");
        return jwk;
    }

    /** The JSON Web Key Set served at the jwks endpoint. */
    public Map<String, Object> jwks() {
        return Map.of("keys", java.util.List.of(jwk()));
    }

    private static byte[] unsigned32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }
}
