package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.EnumSet;

public enum Ctap2Method {

	MAKE_CREDENTIAL(0x01),
	GET_ASSERTION(0x02),
	GET_INFO(0x04),
	CLIENT_PIN(0x06),
	RESET(0x07),
	GET_NEXT_ASSERTION(0x08),
	UNKNOWN();

	private Byte id;

	private Ctap2Method() {
		this.id = null;
	}
	
	private Ctap2Method(int id) {
		this.id = (byte) id;
	}

	static Ctap2Method from(byte b) {
		return EnumSet.allOf(Ctap2Method.class).stream()
				.filter(c -> c.id.byteValue() == b)
				.findFirst()
				.orElse(UNKNOWN);
	}

	public byte[] asBytes() {
		return new byte[] { id };
	}
}
