package com.scivicslab.visaissuer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/** The grants the issuer signs, read from a JSON file: an array of {sub, value, source, by, asserted}. */
public final class GrantStore {

    private final List<Grant> grants;

    public GrantStore(List<Grant> grants) {
        this.grants = List.copyOf(grants);
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
        return grants.stream().filter(g -> g.sub().equals(sub)).toList();
    }
}
