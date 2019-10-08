package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.Arrays;

import org.immutables.value.Value;

@Value.Immutable
public abstract class ContinuationPacket {

	private static final int HEADER_SIZE = 5;
	
	static final ContinuationPacket from(Packet p) {
		byte[] rawBytes = p.rawPayload();
		int sequenceNumber = rawBytes[4];
		byte[] data = Arrays.copyOfRange(rawBytes, HEADER_SIZE, rawBytes.length);

		return ImmutableContinuationPacket.builder()
				.channelId(p.channelId())
				.sequenceNumber(sequenceNumber)
				.data(data)
				.build();
	}

	public abstract ChannelId channelId();
	public abstract int sequenceNumber();
	public abstract byte[] data();
}
