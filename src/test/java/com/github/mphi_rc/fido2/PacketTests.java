package com.github.mphi_rc.fido2;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.BigIntegers;
import org.junit.Test;

import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.ContinuationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.HidCommand;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableContinuationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutableInitializationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutablePacket;
import com.github.mphi_rc.fido2.protocol.usbhid.InitializationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.Packet;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import com.google.common.io.BaseEncoding;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

public class PacketTests {

	static final ChannelId CHANNEL_EXPECTED = ImmutableChannelId.of(new byte[] {0x00, 0x08, 0x00, 0x01});

	private static byte[] hexToBytes(String hex) {
		return BaseEncoding.base16().lowerCase().decode(hex);
	}

	@Test
	public void registerResponse1() throws Exception {
		Packet p1 = ImmutablePacket.of(PacketSamples.REGISTER_RESPONSE_1);
		Packet p2 = ImmutablePacket.of(PacketSamples.REGISTER_RESPONSE_2);
		RawMessage m = RawMessage.from(p1.asInitializationPacket().get(), p2.asContinuationPacket().get());
		assertEquals(HidCommand.CBOR, m.command());
		System.out.println(CborDecoder.decode(m.payload()));
	}
	
	@Test
	public void registerResponse2() throws Exception {
		
		
		
		
		Packet p1 = ImmutablePacket.of(hexToBytes("000800019003ee00a301667061636b65640258c474a6ea9213c99c2f74b22492b320cf40262a94c1a950a0397f29250b60841ef04100000004cb69481e8ff740"));
		Packet p2 = ImmutablePacket.of(hexToBytes("00080001003993ec0a2729a154a800405811ae9c13cd9509f28969172a153ec9f2152e8eff03fddc11c2290c9fb93ed73a99bd0afb4ec93801acf4de5a975a1f"));
		Packet p3 = ImmutablePacket.of(hexToBytes("0008000101c6d7b0fca2a0b386fbbb3a1dfc1a1765a50102032620012158204a6368ab03308c7252a009929fb82e9da3545b5c8258d7907261560819d07ba222"));
		Packet p4 = ImmutablePacket.of(hexToBytes("0008000102582015742300abb1d448bf5cdcee8e081a49c3c934d538767c29523403c78a66062e03a363616c67266373696758473045022100fdd6f6a6838418"));
		Packet p5 = ImmutablePacket.of(hexToBytes("0008000103fd03f891fb5c286e349d1c75c38d28b2b9beddbfaa0b37b0c70220385f12a2dab796f128b61495d5ef17ce1e5d78eba6a615529c2d3861f44b5469"));
		Packet p6 = ImmutablePacket.of(hexToBytes("000800010463783563815902c1308202bd308201a5a003020102020418ac46c0300d06092a864886f70d01010b0500302e312c302a0603550403132359756269"));
		Packet p7 = ImmutablePacket.of(hexToBytes("0008000105636f2055324620526f6f742043412053657269616c203435373230303633313020170d3134303830313030303030305a180f323035303039303430"));
		Packet p8 = ImmutablePacket.of(hexToBytes("000800010630303030305a306e310b300906035504061302534531123010060355040a0c0959756269636f20414231223020060355040b0c1941757468656e74"));
		Packet p9 = ImmutablePacket.of(hexToBytes("0008000107696361746f72204174746573746174696f6e3127302506035504030c1e59756269636f205532462045452053657269616c20343133393433343838"));
		Packet p10 = ImmutablePacket.of(hexToBytes("00080001083059301306072a8648ce3d020106082a8648ce3d0301070342000479ea3b2c7c49701062230cd23feb60e5293171d483f100be859d6b0f83970301"));
		Packet p11 = ImmutablePacket.of(hexToBytes("0008000109b546cdd46ecfcae3e3f30f81e9ed62bd268d4c1ebd37b3bcbe92a8c2aeeb4e3aa36c306a302206092b0601040182c40a020415312e332e362e312e"));
		Packet p12 = ImmutablePacket.of(hexToBytes("000800010a342e312e34313438322e312e373013060b2b0601040182e51c0201010404030205203021060b2b0601040182e51c01010404120410cb69481e8ff7"));
		Packet p13 = ImmutablePacket.of(hexToBytes("000800010b403993ec0a2729a154a8300c0603551d130101ff04023000300d06092a864886f70d01010b05000382010100979d0397d860f82ee15d311c796eba"));
		Packet p14 = ImmutablePacket.of(hexToBytes("000800010cfb22faa7e084d9bab4c61bbb57f3e6b4c18a4837b85c3c4edbe48343f4d6a5d9b1ceda8ae1fed491292173058e5ee1cbdd6bdac07557c6a0e8d368"));
		Packet p15 = ImmutablePacket.of(hexToBytes("000800010d25ba159e7fb5ad8cdaf804868cf90e8f1f8aea17c016b55c2a7ad497c894fb71d753d79b9a484b6c376d723b998d2e1d4306bf1033b5aef8cca5cb"));
		Packet p16 = ImmutablePacket.of(hexToBytes("000800010eb2568b6924226d22a358ab7d87e4ac5f2e091aa71579f3a56909497d72f54e06bac1c3b4413bba5eaf94c3b64f34f9eba41acb6ae283776d364653"));
		Packet p17 = ImmutablePacket.of(hexToBytes("000800010f7848fee884bdddf5b1ba579854cffdcebac344059527e56dd598f8f566715abe4301dd191130e6b9f0c640391253e229803f3aef274bedbfde3fcb"));
		Packet p18 = ImmutablePacket.of(hexToBytes("0008000110bd42ead679000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
		RawMessage m = RawMessage.from(p1.asInitializationPacket().get(), p2.asContinuationPacket().get(), p3.asContinuationPacket().get(), p4.asContinuationPacket().get(),
				p5.asContinuationPacket().get(), p6.asContinuationPacket().get(), p7.asContinuationPacket().get(), p8.asContinuationPacket().get(), p9.asContinuationPacket().get(),
				p10.asContinuationPacket().get(), p11.asContinuationPacket().get(), p12.asContinuationPacket().get(), p13.asContinuationPacket().get(), p14.asContinuationPacket().get(),
				p15.asContinuationPacket().get(), p16.asContinuationPacket().get(), p17.asContinuationPacket().get(), p18.asContinuationPacket().get());
		assertEquals(HidCommand.CBOR, m.command());
		List<DataItem> payload = CborDecoder.decode(m.payload());
		System.out.println(payload);
		byte[] authData = ((ByteString)((Map)payload.get(1)).get(new UnsignedInteger(2))).getBytes();
		byte[] signature = ((ByteString)((Map)((Map)payload.get(1)).get(new UnsignedInteger(3))).get(new UnicodeString("sig"))).getBytes();
		

		System.out.println("auth data: " + Arrays.toString(authData));
		System.out.println("sig: " + Arrays.toString(signature));
		System.out.println("b16(sig) = " + BaseEncoding.base16().encode(signature));
		
		
		ByteBuffer authDataBuf = ByteBuffer.wrap(authData);
		byte[] rpIdHash = new byte[32];
		authDataBuf.get(rpIdHash);

		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] expected = sha256.digest("webauthn.io".getBytes(StandardCharsets.UTF_8));
		System.out.println(Arrays.toString(expected));
		System.out.println(Arrays.toString(rpIdHash));
		
		BitSet flags = BitSet.valueOf(new byte[] { authDataBuf.get()});
		System.out.println(flags.get(0));
		System.out.println(flags.get(1));
		System.out.println(flags.get(6));
		
		System.out.println("sign count = " + authDataBuf.get());
		System.out.println("sign count = " + authDataBuf.get());
		System.out.println("sign count = " + authDataBuf.get());
		System.out.println("sign count = " + authDataBuf.get());
		
		byte[] attestedCredentialData = new byte[authDataBuf.remaining()];
		authDataBuf.get(attestedCredentialData);
		
		System.out.println(BaseEncoding.base16().encode(attestedCredentialData));
		
		
		ByteBuffer acd = ByteBuffer.wrap(attestedCredentialData);
		byte[] aaguid = new byte[16];
		acd.get(aaguid);
		System.out.println("aaguid: " + Arrays.toString(aaguid));
		System.out.println("length = " + acd.get());
		System.out.println("length = " + acd.get());
		byte[] rest = new byte[64];
		acd.get(rest);
		System.out.println("credentialID = " + BaseEncoding.base16().encode(rest));
		
		byte[] remaining = new byte[acd.remaining()];
		acd.get(remaining);
		
		DataItem coseKey = CborDecoder.decode(remaining).get(0);
		byte[] y = ((ByteString) ((Map)coseKey).get(new NegativeInteger(-3))).getBytes();
		byte[] x = ((ByteString) ((Map)coseKey).get(new NegativeInteger(-2))).getBytes();
		System.out.println();
		System.out.println(Arrays.toString(x));
		System.out.println(x.length);
		System.out.println(Arrays.toString(y));
		System.out.println(y.length);
		
		System.out.println("x = " + BaseEncoding.base16().encode(x));
		System.out.println("y = " + BaseEncoding.base16().encode(y));
		
		SecP256R1Curve curve = new SecP256R1Curve();
		ECPoint point = curve.createPoint(BigIntegers.fromUnsignedByteArray(x), BigIntegers.fromUnsignedByteArray(y));
		
		ECNamedCurveParameterSpec ecParameters  = ECNamedCurveTable.getParameterSpec("P-256");
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameters);
        KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        
        
        byte[] clientDataHashFromRequest = BaseEncoding.base16().decode("542714A4D5065648ADBA18BBD96FFFF7A22724730F09001C6ED84BCA2FECFD3C");
        Signature s = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
        s.initVerify(kf.generatePublic(pubSpec));
        s.update(authData);
        s.update(clientDataHashFromRequest);
        boolean b = s.verify(signature);
        
        System.out.println(b);
		
	}
	
	@Test
	public void registerRequest1() {
		Packet p = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_1);
		assertEquals(ChannelId.broadcast(), p.channelId());
		assertEquals(Optional.empty(), p.asContinuationPacket());

		InitializationPacket ip = p.asInitializationPacket().get();
		assertEquals(HidCommand.INIT, ip.command());
		assertEquals(false, ip.isFragmented());
		assertEquals(8, ip.messageLength());

		byte[] expectedData = BaseEncoding.base16().lowerCase().decode("6e17b2ec178f66a700"
				+ "0000000000000000"
				+ "0000000000000000"
				+ "0000000000000000"
				+ "0000000000000000"
				+ "0000000000000000"
				+ "0000000000000000");
		assertArrayEquals(expectedData, ip.data());
	}

	@Test
	public void registerRequest2() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_2);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asContinuationPacket());

		InitializationPacket expected = ImmutableInitializationPacket.builder()
				.channelId(CHANNEL_EXPECTED)
				.messageLength(1)
				.command(HidCommand.CBOR)
				.packetSize(raw.rawPayload().length)
				.data(hexToBytes("04"
						+ "0000000000000000"
						+ "0000000000000000"
						+ "0000000000000000"
						+ "0000000000000000"
						+ "0000000000000000"
						+ "0000000000000000"
						+ "0000000000000000"))
				.build();
		InitializationPacket actual = raw.asInitializationPacket().get();
		assertEquals(expected, actual);
		assertEquals(false, actual.isFragmented());
	}

	@Test
	public void registerRequest3() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_3);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asContinuationPacket());

		InitializationPacket expected = ImmutableInitializationPacket.builder()
				.channelId(CHANNEL_EXPECTED)
				.messageLength(349)
				.command(HidCommand.CBOR)
				.packetSize(raw.rawPayload().length)
				.data(hexToBytes("01"
						+ "a5015820542714a4"
						+ "d5065648adba18bb"
						+ "d96ffff7a2272473"
						+ "0f09001c6ed84bca"
						+ "2fecfd3c02a26269"
						+ "646b776562617574"
						+ "686e2e696f646e61"))
				.build();
		InitializationPacket actual = raw.asInitializationPacket().get();
		assertEquals(expected, actual);
		assertEquals(true, actual.isFragmented());
	}

	@Test
	public void registerRequest4() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_4);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asInitializationPacket());

		ContinuationPacket expected = ImmutableContinuationPacket.builder()
				.sequenceNumber(0)
				.channelId(CHANNEL_EXPECTED)
				.data(hexToBytes("6d656b"
						+ "776562617574686e"
						+ "2e696f03a3626964"
						+ "4ab19e0300000000"
						+ "000000646e616d65"
						+ "646d6174326b6469"
						+ "73706c61794e616d"
						+ "65646d617432048a"))
				.build();
		ContinuationPacket actual = raw.asContinuationPacket().get();
		assertEquals(expected, actual);
	}

	@Test
	public void registerRequest5() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_5);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asInitializationPacket());

		ContinuationPacket expected = ImmutableContinuationPacket.builder()
				.sequenceNumber(1)
				.channelId(CHANNEL_EXPECTED)
				.data(hexToBytes("a26361"
						+ "6c67266474797065"
						+ "6a7075626c69632d"
						+ "6b6579a263616c67"
						+ "382264747970656a"
						+ "7075626c69632d6b"
						+ "6579a263616c6738"
						+ "2364747970656a70"))
				.build();
		ContinuationPacket actual = raw.asContinuationPacket().get();
		assertEquals(expected, actual);
	}

	@Test
	public void registerRequest6() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_6);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asInitializationPacket());

		ContinuationPacket expected = ImmutableContinuationPacket.builder()
				.sequenceNumber(2)
				.channelId(CHANNEL_EXPECTED)
				.data(hexToBytes("75626c"
						+ "69632d6b6579a263"
						+ "616c673901006474"
						+ "7970656a7075626c"
						+ "69632d6b6579a263"
						+ "616c673901016474"
						+ "7970656a7075626c"
						+ "69632d6b6579a263"))
				.build();
		ContinuationPacket actual = raw.asContinuationPacket().get();
		assertEquals(expected, actual);
	}

	@Test
	public void registerRequest7() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_7);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asInitializationPacket());

		ContinuationPacket expected = ImmutableContinuationPacket.builder()
				.sequenceNumber(3)
				.channelId(CHANNEL_EXPECTED)
				.data(hexToBytes("616c67"
						+ "3901026474797065"
						+ "6a7075626c69632d"
						+ "6b6579a263616c67"
						+ "382464747970656a"
						+ "7075626c69632d6b"
						+ "6579a263616c6738"
						+ "2564747970656a70"))
				.build();
		ContinuationPacket actual = raw.asContinuationPacket().get();
		assertEquals(expected, actual);
	}

	@Test
	public void registerRequest8() {
		Packet raw = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_8);
		assertEquals(CHANNEL_EXPECTED, raw.channelId());
		assertEquals(Optional.empty(), raw.asInitializationPacket());

		ContinuationPacket expected = ImmutableContinuationPacket.builder()
				.sequenceNumber(4)
				.channelId(CHANNEL_EXPECTED)
				.data(hexToBytes("75626c"
						+ "69632d6b6579a263"
						+ "616c673826647479"
						+ "70656a7075626c69"
						+ "632d6b6579a26361"
						+ "6c67276474797065"
						+ "6a7075626c69632d"
						+ "6b65790580000000"))
				.build();
		ContinuationPacket actual = raw.asContinuationPacket().get();
		assertEquals(expected, actual);
	}
}
