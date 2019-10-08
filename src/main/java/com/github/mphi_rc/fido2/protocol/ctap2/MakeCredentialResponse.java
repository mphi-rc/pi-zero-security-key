package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.List;

import org.immutables.value.Value;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;

@Value.Immutable
public abstract class MakeCredentialResponse {

	private static final byte FORMAT_KEY = 0x01;
	private static final byte AUTH_DATA_KEY = 0x02;
	private static final byte ATTESTATION_STATEMENT_KEY = 0x03;

	public abstract String format();
	public abstract byte[] authData();
	public abstract byte[] signature();
	public abstract int algorithm();

	public List<DataItem> asCborMap() {
		return new CborBuilder()
				.addMap()
					.put(FORMAT_KEY, format())
					.put(AUTH_DATA_KEY, authData())
					.putMap(ATTESTATION_STATEMENT_KEY)
						.put("alg", algorithm())
						.put("sig", signature())
					.end()
				.end()
				.build();
	}
}
