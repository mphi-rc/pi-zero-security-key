package com.github.mphi_rc.fido2.authenticator.user;

public interface UserVerifier {
	boolean isRegistrationApproved(String relayingPartyId);
	boolean isAuthenticationApproved(String relayingPartyId);
}
