package com.github.mphi_rc.fido2;

import org.junit.Test;

import com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialRequest;
import com.github.mphi_rc.fido2.protocol.usbhid.ContinuationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.ImmutablePacket;
import com.github.mphi_rc.fido2.protocol.usbhid.InitializationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.Packet;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import com.google.common.io.BaseEncoding;

import co.nstant.in.cbor.CborException;

public class MessageTests {

	@Test
	public void registerRequest1() {
		Packet p = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_1);
		InitializationPacket ip = p.asInitializationPacket().get();
		RawMessage m = RawMessage.from(ip);
		System.out.println(m);
	}
	
	@Test
	public void registerRequest2() {
		Packet p = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_2);
		InitializationPacket ip = p.asInitializationPacket().get();
		RawMessage m = RawMessage.from(ip);
		System.out.println(m);
	}
	
	@Test
	public void registerRequestLast() throws CborException {
		Packet p = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_3);
		InitializationPacket ip = p.asInitializationPacket().get();
		
		Packet p2 = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_4);
		ContinuationPacket cp2 = p2.asContinuationPacket().get();
		
		Packet p3 = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_5);
		ContinuationPacket cp3 = p3.asContinuationPacket().get();
		
		Packet p4 = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_6);
		ContinuationPacket cp4 = p4.asContinuationPacket().get();
		
		Packet p5 = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_7);
		ContinuationPacket cp5 = p5.asContinuationPacket().get();
		
		Packet p6 = ImmutablePacket.of(PacketSamples.REGISTER_REQUEST_8);
		ContinuationPacket cp6 = p6.asContinuationPacket().get();
		
		RawMessage m = RawMessage.from(ip, cp2, cp3, cp4, cp5, cp6);
		byte[] params = new byte[m.payload().length - 1];
		System.arraycopy(m.payload(), 1, params, 0, m.payload().length - 1);
		MakeCredentialRequest r = MakeCredentialRequest.fromBytes(params);
		System.out.println(BaseEncoding.base16().encode(r.clientDataHash()));
	}
}
