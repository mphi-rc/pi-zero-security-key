package com.github.mphi_rc.fido2.authenticator;

import java.util.Collection;

import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;


public interface CredentialStore {
	Collection<Credential> getCredentials(String relayingPartyId);
	Credential saveCredential(String relayingPartyId, byte[] userId, AttestationKeyPair keyPair);
	void incrementCredentialCounter(String relayingPartyId, AttestationKeyPair keyPair);
}
