package com.github.mphi_rc.fido2.protocol.usbhid.command;

import java.util.BitSet;

import org.immutables.value.Value;

import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;

@Value.Immutable
public interface InitResponsePayload {

	byte[] nonce();
	ChannelId channel();
	
	default byte ctapHidVersion() {
		return 0x02;
	}
	
	default byte deviceVersionMajor() {
		return 0;
	}
	
	default byte deviceVersionMinor() {
		return 0;
	}
	
	default byte deviceVersionBuild() {
		return 0;
	}

	default boolean supportsWink() {
		return false;
	}

	default boolean supportsCbor() {
		return true;
	}

	default boolean supportsMsg() {
		return false;
	}

	default byte[] asBytes() {
		BitSet capabilityFlags = new BitSet(3);
		if (supportsWink()) {
			capabilityFlags.set(0);
		}
		if (supportsCbor()) {
			capabilityFlags.set(1);
		}
		if (!supportsMsg()) {
			capabilityFlags.set(2);
		}
		byte capabilities = capabilityFlags.toByteArray()[0];
		
		byte[] response = new byte[17];
		System.arraycopy(nonce(), 0, response, 0, 8);
		System.arraycopy(channel().id(), 0, response, 8, 4);
		response[12] = ctapHidVersion();
		response[13] = deviceVersionMajor();
		response[14] = deviceVersionMinor();
		response[15] = deviceVersionBuild();
		response[16] = capabilities;
		return response;
	}
}
