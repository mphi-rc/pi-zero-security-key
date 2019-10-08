package com.github.mphi_rc.fido2.authenticator.user;

public class AlwaysAllowUserVerifier implements UserVerifier {

	@Override
	public boolean isRegistrationApproved(String relayingPartyId) {
		return true;
	}

	@Override
	public boolean isAuthenticationApproved(String relayingPartyId) {
		return true;
	}

}
