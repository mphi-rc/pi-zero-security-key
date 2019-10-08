package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.EnumSet;
import java.util.Objects;

public enum HidCommand {
	
	MSG(0x03),
	CBOR(0x10),
	INIT(0x06),
	PING(0x01),
	CANCEL(0x11),
	ERROR(0x3F),
	WINK(0x08),
	LOCK(0x04),
	UNKNOWN;

	private Byte id;
	
	private HidCommand() {}
	
	private HidCommand(int id) {
		this.id = (byte) id;
	}
	
	static HidCommand from(byte b) {
		return EnumSet.allOf(HidCommand.class).stream()
				.filter(c -> !Objects.isNull(c.id) && c.id.byteValue() == b)
				.findFirst()
				.orElse(UNKNOWN);
	}
	
	public byte asByte() {
		return id;
	}
}
