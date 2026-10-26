package com.scivicslab.visaissuer;

/**
 * One controlled-access grant that the Visa issuer turns into a ControlledAccessGrants Visa.
 *
 * @param sub      subject of the Visa (the researcher identifier inside this issuer)
 * @param value    URL of the dataset the researcher may read
 * @param source   URL of the organisation that made the decision (for example a Data Access Committee)
 * @param by       authority of the decision: self, peer, system, so or dac
 * @param asserted time the decision was made, in epoch seconds
 */
public record Grant(String sub, String value, String source, String by, long asserted) {
}
