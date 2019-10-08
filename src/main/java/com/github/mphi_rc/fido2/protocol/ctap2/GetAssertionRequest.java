package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.immutables.value.Value;

import com.google.common.collect.Iterables;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

@Value.Immutable
public abstract class GetAssertionRequest {

	private static final byte RELAYING_PARTY_ID_KEY = 0x01;
	private static final byte CLIENT_DATA_HASH_KEY = 0x02;
	private static final byte ALLOW_LIST_KEY = 0x03;
	private static final byte PIN_AUTH_KEY = 0x06;
	private static final byte PIN_PROTOCOL_VERSION_KEY = 0x07;

	public static GetAssertionRequest fromBytes(byte[] bytes) throws CborException {
		List<DataItem> values = CborDecoder.decode(bytes);

		Map map = (Map) Iterables.getFirst(values, null);
		if (Objects.isNull(map)) {
			throw new CborException("Empty CBOR request");
		}
		ByteString clientDataHash = (ByteString) map.get(new UnsignedInteger(CLIENT_DATA_HASH_KEY));
		if (Objects.isNull(clientDataHash)) {
			throw new CborException("The client data hash is missing");
		}

		UnicodeString relayingPartyId = (UnicodeString) map.get(new UnsignedInteger(RELAYING_PARTY_ID_KEY));
		if (Objects.isNull(relayingPartyId)) {
			throw new CborException("The relaying party ID is missing");
		}
		
		Array allowList = (Array) map.get(new UnsignedInteger(ALLOW_LIST_KEY));
		ArrayList<byte[]> publicKeyIds = new ArrayList<>();
		if (!Objects.isNull(relayingPartyId)) {
			for (DataItem item : allowList.getDataItems()) {
				ByteString id = ((ByteString) ((Map) item).get(new UnicodeString("id")));
				publicKeyIds.add(id.getBytes());
			}
		}
		
		ImmutableGetAssertionRequest.Builder builder = ImmutableGetAssertionRequest.builder()
				.clientDataHash(clientDataHash.getBytes())
				.relayingPartyId(relayingPartyId.getString())
				.publicKeyIds(publicKeyIds);
		
		ByteString pinAuth = (ByteString) map.get(new UnsignedInteger(PIN_AUTH_KEY));
		if (!Objects.isNull(pinAuth)) {
			builder.pinAuth(pinAuth.getBytes());
		}

		UnsignedInteger pinProtocolVersion = (UnsignedInteger) map.get(new UnsignedInteger(PIN_PROTOCOL_VERSION_KEY));
		if (!Objects.isNull(pinProtocolVersion)) {
			builder.pinProtocolVersion(pinProtocolVersion.getValue().intValue());
		}
		
		return builder.build();
	}

	public abstract String relayingPartyId();
	public abstract byte[] clientDataHash();
	public abstract Set<byte[]> publicKeyIds();
	public abstract Optional<byte[]> pinAuth();
	public abstract Optional<Integer> pinProtocolVersion();

}
