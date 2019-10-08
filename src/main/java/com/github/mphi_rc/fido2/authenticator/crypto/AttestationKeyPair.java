package com.github.mphi_rc.fido2.authenticator.crypto;

import java.io.ByteArrayOutputStream;
import java.util.List;

import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.DataItem;

public interface AttestationKeyPair {
	Algorithm namedCurve();
	byte[] publicKey();
	byte[] privateKey();
	List<DataItem> getCborEncodedPublicKey();
	byte[] sign(AuthenticatorData authData, byte[] clientDataHash);

	default byte[] encodeAttestedCredentialData(byte[] aaguid, byte[] credentialId) {
		try {
			byte credIdLengthHigh = (byte) (credentialId.length & 0xFF00);
			byte credIdLengthLow = (byte) (credentialId.length & 0x00FF);
			ByteArrayOutputStream encoded = new ByteArrayOutputStream();
			encoded.write(aaguid);
			encoded.write(credIdLengthHigh);
			encoded.write(credIdLengthLow);
			encoded.write(credentialId);
			new CborEncoder(encoded).encode(getCborEncodedPublicKey());
			return encoded.toByteArray();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
