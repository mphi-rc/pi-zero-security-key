package com.github.mphi_rc.fido2;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;

import com.github.mphi_rc.fido2.ConfigurationFile;
import com.github.mphi_rc.fido2.authenticator.Authenticator;
import com.github.mphi_rc.fido2.authenticator.ConfigurationCredentialStore;
import com.github.mphi_rc.fido2.authenticator.PinState;
import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorRequestHandler;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2Method;
import com.github.mphi_rc.fido2.protocol.ctap2.MakeCredentialRequest;
import com.github.mphi_rc.fido2.protocol.ctap2.pin.PinRequestHandler;
import com.github.mphi_rc.fido2.protocol.usbhid.UsbHidRequestHandler;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;


public class RegistrationMessageDeserializationTests {

	@Test
	public void requireResidentKey() throws CborException {
		byte[] requestCborPayload = rawMakeCredentialRequest(RegistrationMessages.REQUIRE_RESIDENT_KEY2);
		
		System.out.println(CborDecoder.decode(requestCborPayload));
		
		MakeCredentialRequest makeCredentialRequest = MakeCredentialRequest.fromBytes(requestCborPayload);
		System.out.println(makeCredentialRequest);
	}
	
	private UsbHidRequestHandler getTestHandler() {
		ConfigurationFile config = ConfigurationFile.defaultPath();
		PinState pinState = new PinState(config);
		PinRequestHandler pin = new PinRequestHandler(pinState);
		Authenticator auth = new Authenticator(config, new ConfigurationCredentialStore(config), pinState);
		AuthenticatorRequestHandler authHandler = new AuthenticatorRequestHandler(auth, pin);
		return new UsbHidRequestHandler(authHandler);
	}
	
	private byte[] rawMakeCredentialRequest(byte[] rawMessage) {
		ByteBuffer buf = ByteBuffer.wrap(rawMessage);
		byte[] channelId = new byte[4];
		buf.get(channelId);
		
		byte[] hidCommand = new byte[1];
		buf.get(hidCommand);
		
		byte[] payload = new byte[buf.remaining()];
		buf.get(payload);
		
		ByteBuffer requestPayload = ByteBuffer.wrap(payload);
		byte[] method = new byte[1];
		requestPayload.get(method);
		
		Assert.assertArrayEquals(Ctap2Method.MAKE_CREDENTIAL.asBytes(), method);
		byte[] requestCborPayload = new byte[requestPayload.remaining()];
		requestPayload.get(requestCborPayload);
		
		return requestCborPayload;
	}
}
