package com.scivicslab.visaissuer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The grants the issuer signs: an array of {sub, value, source, by, asserted}. They are read from a JSON file when
 * the process starts and can be replaced at run time, so that a test can give and take away grants.
 */
public final class GrantStore {

    private final AtomicReference<List<Grant>> grants;
    private final Map<String, List<String>> foreignVisas = new ConcurrentHashMap<>();

    public GrantStore(List<Grant> grants) {
        this.grants = new AtomicReference<>(List.copyOf(grants));
    }

    public static GrantStore fromFile(Path file) {
        try {
            return new GrantStore(new ObjectMapper().readValue(Files.readAllBytes(file), new TypeReference<List<Grant>>() {
            }));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read the grants file " + file, e);
        }
    }

    public List<Grant> forSubject(String sub) {
        return grants.get().stream().filter(g -> g.sub().equals(sub)).toList();
    }

    public List<Grant> all() {
        return grants.get();
    }

    /** Replaces all grants. */
    public void replace(List<Grant> newGrants) {
        grants.set(List.copyOf(newGrants));
    }

    /** Visas of other issuers that the Passport of a subject carries next to the Visas signed here (a test hook). */
    public List<String> foreignVisasOf(String sub) {
        return foreignVisas.getOrDefault(sub, List.of());
    }

    /** Sets the Visas of other issuers for a subject; an empty list removes them. */
    public void setForeignVisas(String sub, List<String> visas) {
        if (visas.isEmpty()) {
            foreignVisas.remove(sub);
        } else {
            foreignVisas.put(sub, List.copyOf(visas));
        }
    }
}
