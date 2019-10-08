package com.github.mphi_rc.fido2.protocol.ctap2;

import java.nio.charset.StandardCharsets;
import java.util.BitSet;
import java.util.Optional;

import org.immutables.value.Value;

import com.google.common.hash.Hashing;

@Value.Immutable
public abstract class AuthenticatorData {
	
	public abstract String relayingPartyId();
	public abstract int signatureCount();
	public abstract boolean isUserPresent();
	public abstract boolean isUserVerified();
	public abstract Optional<byte[]> attestedCredentialData(); 
	
	public byte[] asBytes() {
		byte[] rpIdHash = Hashing.sha256()
				.hashString(relayingPartyId(), StandardCharsets.UTF_8)
				.asBytes();
		
		int size = rpIdHash.length + 1 + 4 + attestedCredentialData()
				.map(bytes -> bytes.length)
				.orElse(0);
		byte[] bytes = new byte[size];
		System.arraycopy(rpIdHash, 0, bytes, 0, 32);
		
		BitSet flags = new BitSet(7);
		if (isUserPresent()) {
			flags.set(0);
		}
		if (isUserVerified()) {
			flags.set(2);
		}
		if (attestedCredentialData().isPresent()) {
			flags.set(6);
		}
		bytes[32] = flags.toByteArray()[0];
		bytes[33] = (byte) ((0xFF000000 & signatureCount()) >> 24);
		bytes[34] = (byte) ((0x00FF0000 & signatureCount()) >> 16);
		bytes[35] = (byte) ((0x0000FF00 & signatureCount()) >> 8);
		bytes[36] = (byte) (0x000000FF & signatureCount());
		attestedCredentialData().ifPresent(d -> {
			System.arraycopy(d, 0, bytes, 37, d.length);
		});
		return bytes;
	}
}
