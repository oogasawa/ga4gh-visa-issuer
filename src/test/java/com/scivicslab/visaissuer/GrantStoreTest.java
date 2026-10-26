package com.scivicslab.visaissuer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

class GrantStoreTest {

    private static Grant grant(String sub, String dataset) {
        return new Grant(sub, "https://example.org/datasets/" + dataset, "https://example.org/committees/0001", "dac", 1);
    }

    @Test
    void grantsAreFoundBySubject() {
        GrantStore store = new GrantStore(List.of(grant("a", "JGAD000001"), grant("b", "JGAD000002")));
        assertEquals(List.of(grant("a", "JGAD000001")), store.forSubject("a"));
        assertEquals(List.of(), store.forSubject("nobody"));
    }

    @Test
    void replacingTheGrantsTakesAwayTheOldOnes() {
        GrantStore store = new GrantStore(List.of(grant("a", "JGAD000001")));
        store.replace(List.of(grant("a", "JGAD000002")));
        assertEquals(List.of(grant("a", "JGAD000002")), store.forSubject("a"));
        store.replace(List.of());
        assertEquals(List.of(), store.all());
    }
}
