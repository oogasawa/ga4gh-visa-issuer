package com.scivicslab.visaissuer;

import java.util.List;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/**
 * The Visa issuer's HTTP endpoints. They have no authentication: this service is a verification fixture
 * that is reachable only inside its namespace, and its grants file holds test data.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class IssuerResource {

    @Inject
    SigningKey signingKey;

    @Inject
    VisaSigner signer;

    @Inject
    GrantStore grants;

    /** The public key that verifies the Visas, as a JSON Web Key Set. */
    @GET
    @Path(".well-known/jwks.json")
    public Map<String, Object> jwks() {
        return signingKey.jwks();
    }

    /** A Passport claim for the subject: one signed ControlledAccessGrants Visa per grant. */
    @GET
    @Path("passport/{sub}")
    public Map<String, Object> passport(@PathParam("sub") String sub) {
        List<String> visas = new java.util.ArrayList<>(grants.forSubject(sub).stream().map(signer::sign).toList());
        visas.addAll(grants.foreignVisasOf(sub));
        return Map.of("ga4gh_passport_v1", visas);
    }

    /** The grants that are signed now. */
    @GET
    @Path("grants")
    public List<Grant> grants() {
        return grants.all();
    }

    /** Replaces all grants; a test uses it to give and to take away a researcher's grant. */
    @PUT
    @Path("grants")
    @Consumes(MediaType.APPLICATION_JSON)
    public List<Grant> replaceGrants(List<Grant> newGrants) {
        grants.replace(newGrants);
        return grants.all();
    }

    /**
     * Visas of other issuers that the Passport of the subject carries next to the Visas signed here. A test uses it
     * to hand the Visas of another issuer to a verifier through the URL the verifier already trusts.
     */
    @PUT
    @Path("passport/{sub}/foreign-visas")
    @Consumes(MediaType.APPLICATION_JSON)
    public List<String> setForeignVisas(@PathParam("sub") String sub, List<String> visas) {
        grants.setForeignVisas(sub, visas);
        return grants.foreignVisasOf(sub);
    }
}
