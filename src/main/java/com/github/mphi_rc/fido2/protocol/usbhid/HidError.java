package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.EnumSet;

public enum HidError {

	/** Command in the request is invalid */
	INVALID_CMD(0x01),

	/** Parameter(s) in the request is invalid */
	INVALID_PAR(0x02),

	/** Length field is invalid for the request */
	INVALID_LEN(0x03),

	/** Sequence does not match expected value */
	INVALID_SEQ(0x04),

	/** Message has timed out */
	MSG_TIMEOUT(0x05),

	/** Device is busy for the requesting channel */
	CHANNEL_BUSY(0x06),

	/** Command requires channel lock */
	LOCK_REQUIRED(0x0A),

	/** Channel ID is not valid */
	INVALID_CHANNEL(0x0B),

	OTHER(0x7F);

	private Byte id;

	private HidError(int id) {
		this.id = (byte) id;
	}

	static HidError from(byte b) {
		return EnumSet.allOf(HidError.class).stream()
				.filter(c -> c.id.byteValue() == b)
				.findFirst()
				.orElse(OTHER);
	}

	public byte[] asBytes() {
		return new byte[] { id };
	}
}
