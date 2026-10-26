package com.scivicslab.visaissuer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

import org.eclipse.microprofile.config.inject.ConfigProperty;

/** Creates the plain objects of this service from the configuration. */
@ApplicationScoped
public class Wiring {

    @ConfigProperty(name = "visa-issuer.issuer")
    String issuer;

    @ConfigProperty(name = "visa-issuer.visa-lifetime-seconds", defaultValue = "3600")
    long lifetimeSeconds;

    @ConfigProperty(name = "visa-issuer.grants-file")
    Optional<String> grantsFile;

    @ConfigProperty(name = "visa-verifier.trusted-issuer")
    String trustedIssuer;

    @ConfigProperty(name = "visa-verifier.jwks-uri")
    String jwksUri;

    @ConfigProperty(name = "visa-verifier.accepted-by", defaultValue = "dac")
    List<String> acceptedBy;

    @ConfigProperty(name = "visa-verifier.trusted-sources")
    Optional<List<String>> trustedSources;

    @Produces
    @ApplicationScoped
    SigningKey signingKey() {
        return SigningKey.generate();
    }

    @Produces
    @ApplicationScoped
    VisaSigner visaSigner(SigningKey key) {
        return new VisaSigner(key, issuer, lifetimeSeconds, Clock.systemUTC());
    }

    @Produces
    @ApplicationScoped
    GrantStore grantStore() {
        return grantsFile.filter(f -> !f.isBlank())
                .map(f -> GrantStore.fromFile(Path.of(f)))
                .orElseGet(() -> new GrantStore(List.of()));
    }

    @Produces
    @ApplicationScoped
    VisaVerifier visaVerifier() {
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        VisaVerifier.JwksSource source = uri -> {
            HttpRequest request = HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(5)).GET().build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("The key set at " + uri + " returned HTTP " + response.statusCode());
            }
            return response.body();
        };
        Set<String> sources = trustedSources.orElse(List.of()).stream().filter(s -> !s.isBlank()).collect(Collectors.toSet());
        return new VisaVerifier(Map.of(trustedIssuer, jwksUri), Set.copyOf(acceptedBy), sources, source, Clock.systemUTC());
    }
}
