package com.github.mphi_rc.fido2.protocol.usbhid;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.BitSet;

import org.immutables.value.Value;

import com.google.common.base.Preconditions;
import com.google.common.primitives.UnsignedBytes;

@Value.Immutable
public abstract class InitializationPacket {

	private static final int HEADER_SIZE_INIT = 7;
	private static final int HEADER_SIZE_CONT = 5;
	private static final int PACKET_TYPE_FLAG_BIT = 7;
	
	static final InitializationPacket from(Packet p) {
		byte[] rawBytes = p.rawPayload();
		int packetSize = rawBytes.length;
		
		int high = UnsignedBytes.toInt(rawBytes[5]) << 8;
		int low = UnsignedBytes.toInt(rawBytes[6]);
		int messageLength = high | low;
		
		BitSet commandBits = BitSet.valueOf(ByteBuffer.wrap(rawBytes, 4, 1));
		commandBits.clear(PACKET_TYPE_FLAG_BIT);
		HidCommand command = HidCommand.from(commandBits.toByteArray()[0]);
		
		byte[] data = Arrays.copyOfRange(rawBytes, 7, rawBytes.length);

		return ImmutableInitializationPacket.builder()
				.channelId(p.channelId())
				.messageLength(messageLength)
				.command(command)
				.data(data)
				.packetSize(packetSize)
				.build();
	}
	
	public abstract ChannelId channelId();
	public abstract HidCommand command();
	public abstract int messageLength();
	public abstract int packetSize();
	public abstract byte[] data();
	
	@Value.Check
	protected void check() {
		int maxMessageLength = 128 * (packetSize() - HEADER_SIZE_CONT) + (packetSize() - HEADER_SIZE_INIT);
		Preconditions.checkArgument(messageLength() <= maxMessageLength, "Message length too big");
	}
	
	@Value.Derived
	public boolean isFragmented() {
		return messageLength() > packetSize() - HEADER_SIZE_INIT;
	}
}
