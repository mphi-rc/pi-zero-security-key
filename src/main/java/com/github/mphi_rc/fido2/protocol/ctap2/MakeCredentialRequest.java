package com.github.mphi_rc.fido2.protocol.ctap2;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.immutables.value.Value;

import com.google.common.collect.Iterables;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

@Value.Immutable
public abstract class MakeCredentialRequest {
	
	private static final byte CLIENT_DATA_HASH_KEY = 0x01;
	private static final byte RELAYING_PARTY_ID_KEY = 0x02;
	private static final byte USER_ID_KEY = 0x03;
	private static final byte SUPPORTED_ALGORITHMS_KEY = 0x04;
	private static final byte PIN_AUTH_KEY = 0x08;
	private static final byte PIN_PROTOCOL_VERSION_KEY = 0x09;
	
	public static MakeCredentialRequest fromBytes(byte[] bytes) throws CborException {
		List<DataItem> values = CborDecoder.decode(bytes);

		Map map = (Map) Iterables.getFirst(values, null);
		if (Objects.isNull(map)) {
			throw new CborException("Empty CBOR request");
		}
		ByteString clientDataHash = (ByteString) map.get(new UnsignedInteger(CLIENT_DATA_HASH_KEY));
		if (Objects.isNull(clientDataHash)) {
			throw new CborException("The client data hash is missing");
		}

		Map relayingParty = (Map) map.get(new UnsignedInteger(RELAYING_PARTY_ID_KEY));
		if (Objects.isNull(relayingParty)) {
			throw new CborException("The relaying party is missing");
		}
		UnicodeString relayingPartyId = (UnicodeString) relayingParty.get(new UnicodeString("id"));
		if (Objects.isNull(relayingPartyId)) {
			throw new CborException("The relaying party ID is missing");
		}

		Map user = (Map) map.get(new UnsignedInteger(USER_ID_KEY));
		if (Objects.isNull(user)) {
			throw new CborException("The user data is missing");
		}
		ByteString userId = (ByteString) user.get(new UnicodeString("id"));
		if (Objects.isNull(userId)) {
			throw new CborException("The user ID is missing");
		}

		Array supportedAlgs = (Array) map.get(new UnsignedInteger(SUPPORTED_ALGORITHMS_KEY));
		if (Objects.isNull(supportedAlgs)) {
			throw new CborException("The supported algorithms field is missing");
		}
		Set<Integer> supportedAlgIds = supportedAlgs.getDataItems().stream()
				.map(item -> ((Map) item).get(new UnicodeString("alg")))
				.map(item -> ((NegativeInteger) item).getValue())
				.map(BigInteger::intValue)
				.collect(Collectors.toSet());

		ImmutableMakeCredentialRequest.Builder builder = ImmutableMakeCredentialRequest.builder()
				.clientDataHash(clientDataHash.getBytes())
				.relayingPartyId(relayingPartyId.getString())
				.userId(userId.getBytes())
				.addAllSupportedAlgorithmIds(supportedAlgIds);
		
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
	
	public abstract byte[] clientDataHash();
	public abstract String relayingPartyId();
	public abstract byte[] userId();
	public abstract Set<Integer> supportedAlgorithmIds();
	public abstract Optional<byte[]> pinAuth();
	public abstract Optional<Integer> pinProtocolVersion();
}
