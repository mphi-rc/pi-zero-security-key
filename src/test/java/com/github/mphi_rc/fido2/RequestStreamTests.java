package com.github.mphi_rc.fido2;

import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_1;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_10;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_2;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_3;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_4;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_5;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_6;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_7;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_8;
import static com.github.mphi_rc.fido2.LoginPackets.AUTHENTICATOR_9;
import static com.github.mphi_rc.fido2.LoginPackets.HOST_1;
import static com.github.mphi_rc.fido2.LoginPackets.HOST_2;
import static com.github.mphi_rc.fido2.LoginPackets.HOST_3;
import static com.github.mphi_rc.fido2.LoginPackets.HOST_4;
import static com.github.mphi_rc.fido2.LoginPackets.HOST_5;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.BigIntegers;
import org.junit.Assert;
import org.junit.Test;

import com.github.mphi_rc.fido2.protocol.PacketInputStream;
import com.github.mphi_rc.fido2.protocol.RequestStream;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2Method;
import com.github.mphi_rc.fido2.protocol.ctap2.GetAssertionRequest;
import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.HidCommand;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableRawMessage;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import com.github.mphi_rc.fido2.protocol.usbhid.command.ImmutableInitResponsePayload;
import com.github.mphi_rc.fido2.protocol.usbhid.command.InitResponsePayload;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

public class RequestStreamTests {
	
	private ChannelId expectedChannelId = ImmutableChannelId.of(new byte[] {0, 8, 0, 2});
	private byte[] expectedNonce = {4, 36, 26, -91, 23, -115, 87, 0};
	
	@Test
	public void whatever() throws Exception {
		
		RequestStream requests = stream(HOST_1, HOST_2, HOST_3, HOST_4, HOST_5);
		RequestStream responses = stream(AUTHENTICATOR_1, AUTHENTICATOR_2, AUTHENTICATOR_2,
				AUTHENTICATOR_3, AUTHENTICATOR_4, AUTHENTICATOR_5, AUTHENTICATOR_6,
				AUTHENTICATOR_7, AUTHENTICATOR_8, AUTHENTICATOR_9, AUTHENTICATOR_10);
		
		RawMessage initExpected = ImmutableRawMessage.builder()
				.channelId(ChannelId.broadcast())
				.command(HidCommand.INIT)
				.payload(expectedNonce)
				.build();
		RawMessage init = requests.readMessage();
		assertEquals(initExpected, init);

		InitResponsePayload initResponsePayload = ImmutableInitResponsePayload.builder()
				.nonce(expectedNonce)
				.channel(expectedChannelId)
				.build();
		RawMessage initResponseExpected = ImmutableRawMessage.builder()
				.channelId(ChannelId.broadcast())
				.command(HidCommand.INIT)
				.payload(initResponsePayload.asBytes())
				.build();
		// yubikey has trailing bytes
		// assertEquals(initResponseExpected, responses.readMessage());
		responses.readMessage();
		
		RawMessage getInfoExpected = ImmutableRawMessage.builder()
				.channelId(expectedChannelId)
				.command(HidCommand.CBOR)
				.payload(Ctap2Method.GET_INFO.asBytes())
				.build();
		RawMessage getInfo = requests.readMessage();
		Assert.assertEquals(getInfoExpected, getInfo);
		
		RawMessage getInfoResponse = responses.readMessage();
		
		RawMessage getAssertion = requests.readMessage();
		byte[] params = new byte[getAssertion.payload().length - 1];
		System.arraycopy(getAssertion.payload(), 1, params, 0, params.length);
		GetAssertionRequest req = GetAssertionRequest.fromBytes(params);
		System.out.println(req);
		
		// skip unknowns (maybe keep-alive?)
		responses.readMessage();
		responses.readMessage();
		responses.readMessage();
		
		RawMessage getAssertionResponse = responses.readMessage();
		params = new byte[getAssertionResponse.payload().length - 1];
		System.arraycopy(getAssertionResponse.payload(), 1, params, 0, params.length);
		
		List<DataItem> getAssertionResponseParams = CborDecoder.decode(params);
		System.out.println(getAssertionResponseParams);
		System.out.println();
		
		ByteString credentialId = (ByteString) ((Map) ((Map) getAssertionResponseParams.get(0)).get(new UnsignedInteger(1))).get(new UnicodeString("id"));
		
		// taken from registration packets
		String expectedCredentialId = "5811AE9C13CD9509F28969172A153EC9F2152E8EFF03FDDC11C2290C9FB93ED73A99BD0AFB4EC93801ACF4DE5A975A1FC6D7B0FCA2A0B386FBBB3A1DFC1A1765";
		Assert.assertEquals(expectedCredentialId, BaseEncoding.base16().encode(credentialId.getBytes()));
		
		ByteString authData = (ByteString) ((Map) getAssertionResponseParams.get(0)).get(new UnsignedInteger(2));
		System.out.println(BaseEncoding.base16().encode(authData.getBytes()));
		
		ByteBuffer authDataBuf = ByteBuffer.wrap(authData.getBytes());
		byte[] rpIdHash = new byte[32];
		authDataBuf.get(rpIdHash);

		byte[] expectedRpidHash = Hashing.sha256().hashString("webauthn.io", StandardCharsets.UTF_8).asBytes();
		Assert.assertArrayEquals(expectedRpidHash, rpIdHash);
		
		BitSet flags = BitSet.valueOf(new byte[] { authDataBuf.get() });
		boolean isUserPresent = flags.get(0);
		boolean isUserVerified = flags.get(2);
		boolean hasAttestedCredentialData = flags.get(6);
		Assert.assertTrue(isUserPresent);
		Assert.assertFalse(isUserVerified);
		Assert.assertFalse(hasAttestedCredentialData);
		
		Assert.assertEquals(authDataBuf.get(), 0);
		Assert.assertEquals(authDataBuf.get(), 0);
		Assert.assertEquals(authDataBuf.get(), 0);
		Assert.assertEquals(authDataBuf.get(), 5);
		Assert.assertFalse(authDataBuf.hasRemaining());
		
		ByteString signature = (ByteString) ((Map) getAssertionResponseParams.get(0)).get(new UnsignedInteger(3));
		System.out.println(BaseEncoding.base16().encode(signature.getBytes()));
		
		byte[] x = BaseEncoding.base16().decode("4A6368AB03308C7252A009929FB82E9DA3545B5C8258D7907261560819D07BA2");
		byte[] y = BaseEncoding.base16().decode("15742300ABB1D448BF5CDCEE8E081A49C3C934D538767C29523403C78A66062E");
		
		SecP256R1Curve curve = new SecP256R1Curve();
		ECPoint point = curve.createPoint(BigIntegers.fromUnsignedByteArray(x), BigIntegers.fromUnsignedByteArray(y));
		
		ECNamedCurveParameterSpec ecParameters  = ECNamedCurveTable.getParameterSpec("P-256");
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        
        
        byte[] clientDataHashFromRequest = BaseEncoding.base16().decode("542714A4D5065648ADBA18BBD96FFFF7A22724730F09001C6ED84BCA2FECFD3C");
        
        Signature s = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        s.initVerify(kf.generatePublic(pubSpec));
        s.update(authData.getBytes());
        s.update(clientDataHashFromRequest);
        boolean isValidSignature = s.verify(signature.getBytes());
        System.out.println("isValidSignature = " + isValidSignature);
		
	}
	
	private RequestStream stream(byte[]... packets) {
		int bufferSize = Arrays.stream(packets)
				.mapToInt(arr -> arr.length)
				.sum();
		ByteBuffer buf = ByteBuffer.allocate(bufferSize);
		for (byte[] packet : packets) {
			buf.put(packet);
		}
		return new RequestStream(new PacketInputStream(new DataInputStream(new ByteArrayInputStream(buf.array()))));
	}
}
