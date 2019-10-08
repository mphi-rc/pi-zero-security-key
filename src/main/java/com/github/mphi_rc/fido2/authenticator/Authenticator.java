package com.github.mphi_rc.fido2.authenticator;

import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.Ed25519AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.user.UserVerifier;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2ResponseCode;
import com.github.mphi_rc.fido2.protocol.ctap2.GetAssertionRequest;
import com.github.mphi_rc.fido2.protocol.ctap2.GetAssertionResponse;
import com.github.mphi_rc.fido2.protocol.ctap2.GetInfoResponse;
import com.github.mphi_rc.fido2.protocol.ctap2.GetInfoResponse.Version;
import com.github.mphi_rc.fido2.protocol.ctap2.ImmutableAuthenticatorData;
import com.github.mphi_rc.fido2.protocol.ctap2.ImmutableGetAssertionResponse;
import com.github.mphi_rc.fido2.protocol.ctap2.ImmutableGetInfoResponse;
import com.github.mphi_rc.fido2.protocol.ctap2.ImmutableMakeCredentialResponse;
import com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialResponse;

public class Authenticator {

	private static final Logger log = LoggerFactory.getLogger(Authenticator.class);

	private final ConfigurationFile config;
	private final CredentialStore credentialStore;
	private final PinState pinState;
	private final UserVerifier userVerifier;

	public Authenticator(ConfigurationFile config, CredentialStore credentialStore, PinState pinState) {
		this.config = config;
		this.credentialStore = credentialStore;
		this.pinState = pinState;
		this.userVerifier = config.userVerifier();
	}

	public Result<MakeCredentialResponse, Ctap2ResponseCode> makeCredential(byte[] clientDataHash, String relayingPartyId,
			byte[] userId, Set<Integer> supportedAlgorithmIds, Optional<byte[]> pinAuth) {

		Algorithm algorithmToUse = null;
		for (Algorithm algorithm : config.enabledAlgorithms()) {
			if (supportedAlgorithmIds.contains(algorithm.getCoseAlgorithmId())) {
				algorithmToUse = algorithm;
				break;
			}
		}
		if (Objects.isNull(algorithmToUse)) {
			return Result.err(Ctap2ResponseCode.UNSUPPORTED_ALGORITHM);
		}

		if (!userVerifier.isRegistrationApproved(relayingPartyId)) {
			return Result.err(Ctap2ResponseCode.OPERATION_DENIED);
		}

		AttestationKeyPair keypair = null;
		switch (algorithmToUse) {
		case Ed25519:
			keypair = Ed25519AttestationKeyPair.generate();
			break;
		case P256_ECDSA:
			keypair = P256AttestationKeyPair.generate();
			break;
		}
		Credential cred = credentialStore.saveCredential(relayingPartyId, userId, keypair);

		byte[] attestedCredentialData = keypair.encodeAttestedCredentialData(config.getAaguid(), cred.id());

		boolean isUserVerified = false;
		// According to the FIDO2 spec, we should return PIN_NOT_SET or PIN_INVALID if len(pinAuth) == 0. But Google Chrome doesn't
		// appear to react to that and times out, so we work around this by returning a "successful" non-user verified response.
		
		if (pinAuth.isPresent() && pinAuth.get().length != 0) {
			
			Optional<Ctap2ResponseCode> maybeError = pinState.isPinAuthValid(clientDataHash, pinAuth.get());
			if (maybeError.isPresent()) {
				log.info("pin auth was present but did not succeed, sending {}", maybeError.get());
				return Result.err(maybeError.get());
			}
			log.info("pin auth succeeded");
			isUserVerified = true;
		}

		AuthenticatorData authData = ImmutableAuthenticatorData.builder()
				.relayingPartyId(relayingPartyId)
				.attestedCredentialData(attestedCredentialData)
				.isUserPresent(true)
				.isUserVerified(isUserVerified)
				.signatureCount(0)
				.build();

		byte[] signature = keypair.sign(authData, clientDataHash);
		MakeCredentialResponse response = ImmutableMakeCredentialResponse.builder()
				.format("packed")
				.signature(signature)
				.algorithm(algorithmToUse.getCoseAlgorithmId())
				.authData(authData.asBytes())
				.build();
		return Result.ok(response);
	}

	public Result<GetAssertionResponse, Ctap2ResponseCode> getAssertion(GetAssertionRequest request) {
		Collection<Credential> creds = credentialStore.getCredentials(request.relayingPartyId());
		if (creds.isEmpty()) {
			return Result.err(Ctap2ResponseCode.NO_CREDENTIALS);
		}

		if (!userVerifier.isAuthenticationApproved(request.relayingPartyId())) {
			return Result.err(Ctap2ResponseCode.OPERATION_DENIED);
		}

		Credential cred;
		if (request.publicKeyIds().isEmpty()) {
			cred = creds.iterator().next();
		} else {
			Optional<Credential> matchingCredential = creds.stream()
					.filter(c -> {
						for (byte[] validId : request.publicKeyIds()) {
							if (Arrays.equals(validId, c.id())) {
								return true;
							}
						}
						return false;
					})
					.findAny();

			if (!matchingCredential.isPresent()) {
				return Result.err(Ctap2ResponseCode.NO_CREDENTIALS);
			}
			cred = matchingCredential.get();
		}

		boolean isUserVerified = false;
		// According to the FIDO2 spec, we should return PIN_NOT_SET or PIN_INVALID if len(pinAuth) == 0. But Google Chrome doesn't
		// appear to react to that and times out, so we work around this by returning a "successful" non-user verified response.
		
		Optional<byte[]> pinAuth = request.pinAuth();  
		if (pinAuth.isPresent() && pinAuth.get().length != 0) {
			Optional<Ctap2ResponseCode> maybeError = pinState.isPinAuthValid(request.clientDataHash(), pinAuth.get());
			if (maybeError.isPresent()) {
				log.info("pin auth was present but did not succeed, sending {}", maybeError.get());
				return Result.err(maybeError.get());
			}
			log.info("pin auth succeeded");
			isUserVerified = true;
		}

		AuthenticatorData authData = ImmutableAuthenticatorData.builder()
				.isUserPresent(true)
				.isUserVerified(isUserVerified)
				.signatureCount(cred.signatureCount() + 1)
				.relayingPartyId(request.relayingPartyId())
				.build();

		AttestationKeyPair keyPair = cred.keyPair();
		byte[] signature = keyPair.sign(authData, request.clientDataHash());
		credentialStore.incrementCredentialCounter(request.relayingPartyId(), keyPair);

		GetAssertionResponse response = ImmutableGetAssertionResponse.builder()
				.credentialId(cred.id())
				.authData(authData.asBytes())
				.signature(signature)
				.userId(cred.userId())
				.build();
		return Result.ok(response);
	}

	public GetInfoResponse getInfo() {
		return ImmutableGetInfoResponse.of(Version.FIDO_2_0, config.getAaguid(), pinState.isPinSet());
	}

	void reset() {
		throw new UnsupportedOperationException("Reset is not implemented");
	}

	void getNextAssertion() {
		throw new UnsupportedOperationException("GetNextAssertion is not implemented");
	}
}
