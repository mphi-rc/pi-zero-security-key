package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.List;

import org.immutables.value.Value;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;

@Value.Immutable
public abstract class GetAssertionResponse {

	private static final byte CREDENTIAL_KEY = 0x01;
	private static final byte AUTH_DATA_KEY = 0x02;
	private static final byte SIGNATURE_KEY = 0x03;

	public abstract byte[] credentialId();
	public abstract byte[] authData();
	public abstract byte[] signature();
	public abstract byte[] userId();

	public List<DataItem> asCborMap() {
		return new CborBuilder()
				.addMap()
					.putMap(CREDENTIAL_KEY)
						.put("id", credentialId())
						.put("type", "public-key")
					.end()
					.put(AUTH_DATA_KEY, authData())
					.put(SIGNATURE_KEY, signature())
				.end()
				.build();
	}
}
