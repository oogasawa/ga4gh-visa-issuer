package com.scivicslab.visaissuer;

import java.util.List;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

/** The verification harness: decides whether a Passport lets a researcher read a dataset. */
@Path("/verify")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class VerifyResource {

    /**
     * @param passport      the Visa JSON Web Tokens of the Passport claim ga4gh_passport_v1
     * @param expectedValue the dataset URL the researcher wants to read
     */
    public record Request(List<String> passport, String expectedValue) {
    }

    @Inject
    VisaVerifier verifier;

    @POST
    public VisaVerifier.Result verify(Request request) {
        return verifier.verifyPassport(request.passport(), request.expectedValue());
    }
}
