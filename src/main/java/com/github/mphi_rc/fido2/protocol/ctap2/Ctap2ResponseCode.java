package com.github.mphi_rc.fido2.protocol.ctap2;

import java.util.EnumSet;

public enum Ctap2ResponseCode {

	OK(0x00),
	CBOR_UNEXPECTED_TYPE(0x11),
	INVALID_CBOR(0x12),
	MISSING_PARAMETER(0x14),
	LIMIT_EXCEEDED(0x15),
	UNSUPPORTED_EXTENSION(0x16),
	CREDENTIAL_EXCLUDED(0x19),
	PROCESSING(0x21),
	INVALID_CREDENTIAL(0x22),
	USER_ACTION_PENDING(0x23),
	OPERATION_PENDING(0x24),
	NO_OPERATIONS(0x25),
	UNSUPPORTED_ALGORITHM(0x26),
	OPERATION_DENIED(0x27),
	KEY_STORE_FULL(0x28),
	NO_OPERATION_PENDING(0x2A),
	UNSUPPORTED_OPTION(0x2B),
	INVALID_OPTION(0x2C),
	KEEPALIVE_CANCEL(0x2D),
	NO_CREDENTIALS(0x2E),
	USER_ACTION_TIMEOUT(0x2F),
	NOT_ALLOWED(0x30),
	PIN_INVALID(0x31),
	PIN_BLOCKED(0x32),
	PIN_AUTH_INVALID(0x33),
	PIN_AUTH_BLOCKED(0x34),
	PIN_NOT_SET(0x35),
	PIN_REQUIRED(0x36),
	PIN_POLICY_VIOLATION(0x37),
	PIN_TOKEN_EXPIRED(0x38),
	REQUEST_TOO_LARGE(0x39),
	ACTION_TIMEOUT(0x3A),
	USER_PRESENCE_REQUIRED(0x3B),
	OTHER(0x7F);

	private Byte id;

	private Ctap2ResponseCode() {
		this.id = null;
	}
	
	private Ctap2ResponseCode(int id) {
		this.id = (byte) id;
	}

	static Ctap2ResponseCode from(byte b) {
		return EnumSet.allOf(Ctap2ResponseCode.class).stream()
				.filter(c -> c.id.byteValue() == b)
				.findFirst()
				.orElse(OTHER);
	}

	public byte[] asBytes() {
		return new byte[] { id };
	}
}
