package com.github.mphi_rc.fido2.authenticator;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.immutables.gson.Gson;
import org.immutables.value.Value;

import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;

@Gson.TypeAdapters
@Value.Immutable
public interface Credential {

	@Value.Parameter
	String relayingPartyId();

	@Value.Parameter
	Instant creation();

	@Value.Parameter
	byte[] userId();

	@Value.Parameter
	AttestationKeyPair keyPair();

	@Value.Parameter
	int signatureCount();
	
	@Value.Derived
	default byte[] id() {
		HashFunction hf = Hashing.murmur3_128();
		HashCode code = hf.newHasher()
			.putString(relayingPartyId(), StandardCharsets.UTF_8)
			.putLong(creation().toEpochMilli())
			.putBytes(userId())
			.putBytes(keyPair().publicKey())
			.hash();
		return code.asBytes();
	}
}
