package com.github.mphi_rc.fido2.protocol.ctap2;

import java.io.ByteArrayOutputStream;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.authenticator.Authenticator;
import com.github.mphi_rc.fido2.authenticator.Result;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.HidCommand;
import com.github.mphi_rc.fido2.protocol.usbhid.HidError;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableRawMessage;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;

public class AuthenticatorRequestHandler {

	private static final Logger log = LoggerFactory.getLogger(AuthenticatorRequestHandler.class);

	private final PinRequestHandler pinRequestHandler;
	private final Authenticator authenticator;

	public AuthenticatorRequestHandler(Authenticator authenticator, PinRequestHandler pinRequestHandler) {
		this.authenticator = authenticator;
		this.pinRequestHandler = pinRequestHandler;
	}

	private RawMessage failure(ChannelId channelId, Ctap2ResponseCode errorCode) {
		return ImmutableRawMessage.builder()
				.channelId(channelId)
				.command(HidCommand.CBOR)
				.payload(errorCode.asBytes())
				.build();
	}

	private byte[] asPayload(Ctap2ResponseCode code, List<DataItem> parameterMap) {
		ByteArrayOutputStream payload = new ByteArrayOutputStream();
		CborEncoder encoder = new CborEncoder(payload);
		CborBuilder builder = new CborBuilder()
				.add(code.asBytes()[0]);
		for (DataItem i : parameterMap) {
			builder = builder.add(i);
		}
		try {
			encoder.encode(builder.build());
		} catch (CborException e) {
			throw new RuntimeException(e);
		}
		return payload.toByteArray();
	}

	public RawMessage handleCborRequest(ChannelId channelId, byte[] payload) {
		if (payload.length == 0) {
			return RawMessage.error(channelId, HidError.INVALID_LEN);
		}

		Ctap2Method method = Ctap2Method.from(payload[0]);

		byte[] params = new byte[payload.length - 1];
		System.arraycopy(payload, 1, params, 0, payload.length - 1);
		try {
			log.debug("Received CBOR request with method {} and body {}", method, CborDecoder.decode(params));
		} catch (CborException e) {
			log.error("Unable to deserialize CBOR parameters", e);
			return failure(channelId, Ctap2ResponseCode.INVALID_CBOR);
		}

		try {
			switch (method) {
			case GET_ASSERTION:
				GetAssertionRequest gar = GetAssertionRequest.fromBytes(params);
				byte[] assertion = authenticator.getAssertion(gar)
						.handleError(err -> asPayload(err, Collections.emptyList()))
						.elseGet(value -> asPayload(Ctap2ResponseCode.OK, value.asCborMap()));
				return ImmutableRawMessage.builder()
						.channelId(channelId)
						.command(HidCommand.CBOR)
						.payload(assertion)
						.build();

			case GET_INFO:
				GetInfoResponse response = authenticator.getInfo();
				log.trace("Authenticator supports options {}", response);
				byte[] info = asPayload(Ctap2ResponseCode.OK, response.asCborMap());
				return ImmutableRawMessage.builder()
						.channelId(channelId)
						.command(HidCommand.CBOR)
						.payload(info)
						.build();

			case MAKE_CREDENTIAL:
				MakeCredentialRequest request = MakeCredentialRequest.fromBytes(params);
				Result<MakeCredentialResponse, Ctap2ResponseCode> result = authenticator.makeCredential(request.clientDataHash(),
						request.relayingPartyId(), request.userId(), request.supportedAlgorithmIds(), request.pinAuth());
				byte[] credential = result
						.handleError(err -> asPayload(err, Collections.emptyList()))
						.elseGet(value -> asPayload(Ctap2ResponseCode.OK, value.asCborMap()));
				return ImmutableRawMessage.builder()
						.channelId(channelId)
						.command(HidCommand.CBOR)
						.payload(credential)
						.build();

			case CLIENT_PIN:

				Map pinParams = (Map) CborDecoder.decode(params).get(0);
				UnsignedInteger pinProtocol = (UnsignedInteger) pinParams.get(new UnsignedInteger(0x01));
				// TODO: handle pinProtocol != 1 somehow
				
				UnsignedInteger subCommand = (UnsignedInteger) pinParams.get(new UnsignedInteger(0x02));
				switch(subCommand.getValue().intValue()) {
				case 0x01: // get retries
					List<DataItem> retries = pinRequestHandler.getRetries();
					return ImmutableRawMessage.builder()
							.channelId(channelId)
							.command(HidCommand.CBOR)
							.payload(asPayload(Ctap2ResponseCode.OK, retries))
							.build();
					
				case 0x02: // get key
					List<DataItem> key = pinRequestHandler.getKeyAgreementKey();
					return ImmutableRawMessage.builder()
							.channelId(channelId)
							.command(HidCommand.CBOR)
							.payload(asPayload(Ctap2ResponseCode.OK, key))
							.build();
					
				case 0x03: // set pin
					Map hostCoseKey = (Map) pinParams.get(new UnsignedInteger(0x03));
					ByteString pinAuth = (ByteString) pinParams.get(new UnsignedInteger(0x04));
					ByteString newPinEnc = (ByteString) pinParams.get(new UnsignedInteger(0x05));
					Ctap2ResponseCode code = pinRequestHandler.setPin(hostCoseKey, newPinEnc.getBytes(), pinAuth.getBytes());
					return ImmutableRawMessage.builder()
							.channelId(channelId)
							.command(HidCommand.CBOR)
							.payload(asPayload(code, Collections.emptyList()))
							.build();
					
				case 0x04: // change pin
					Map hostCoseKey2 = (Map) pinParams.get(new UnsignedInteger(0x03));
					ByteString pinAuth2 = (ByteString) pinParams.get(new UnsignedInteger(0x04));
					ByteString newPinEnc2 = (ByteString) pinParams.get(new UnsignedInteger(0x05));
					ByteString PinHashEnc = (ByteString) pinParams.get(new UnsignedInteger(0x06));
					Ctap2ResponseCode code2 = pinRequestHandler.changePin(hostCoseKey2, PinHashEnc.getBytes(), newPinEnc2.getBytes(), pinAuth2.getBytes());
					return ImmutableRawMessage.builder()
							.channelId(channelId)
							.command(HidCommand.CBOR)
							.payload(asPayload(code2, Collections.emptyList()))
							.build();
					
				case 0x05: // get pin token
					Map hostCoseKey3 = (Map) pinParams.get(new UnsignedInteger(0x03));
					ByteString pinHashEnc2 = (ByteString) pinParams.get(new UnsignedInteger(0x06));
					Result<List<DataItem>, Ctap2ResponseCode> pinToken = pinRequestHandler.getPinToken(hostCoseKey3, pinHashEnc2.getBytes());
					byte[] pinTokenPayload = pinToken.handleError(err -> asPayload(err, Collections.emptyList()))
							.elseGet(val -> asPayload(Ctap2ResponseCode.OK, val));
					return ImmutableRawMessage.builder()
							.channelId(channelId)
							.command(HidCommand.CBOR)
							.payload(pinTokenPayload)
							.build();
				}
				break;
			case RESET:
			case GET_NEXT_ASSERTION:
			default:
				return RawMessage.error(channelId, HidError.INVALID_CMD);
			}

		} catch (CborException e) {
			log.error("Unable to deserialize CBOR", e);
		}
		return failure(channelId, Ctap2ResponseCode.INVALID_CBOR);

	}
}
