package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.Arrays;

import org.immutables.value.Value;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;

@Value.Immutable
public abstract class RawMessage {

	public static RawMessage error(ChannelId channelId, HidError error) {
		return ImmutableRawMessage.builder()
				.channelId(channelId)
				.command(HidCommand.ERROR)
				.payload(error.asBytes())
				.build();
	}
	
	public static RawMessage from(InitializationPacket initial, ContinuationPacket... rest) {
		ImmutableSet.Builder<ChannelId> channelIds = ImmutableSet.<ChannelId>builder().add(initial.channelId());
		int availableBytes = initial.data().length;
		for (ContinuationPacket continuation : rest) {
			channelIds.add(continuation.channelId());
			availableBytes += continuation.data().length;
		}
		Preconditions.checkArgument(channelIds.build().size() == 1, "All packets must be for the same channel ID");
		Preconditions.checkArgument(availableBytes >= initial.messageLength(), "Message length exceeds bytes available to read");

		int lastSequenceNum = -1;
		for (ContinuationPacket packet : rest) {
			int thisSequenceNumber = packet.sequenceNumber();
			Preconditions.checkArgument(thisSequenceNumber != lastSequenceNum, "Continuation packets with duplicate sequence numbers");
			Preconditions.checkArgument(thisSequenceNumber > lastSequenceNum, "Continuation packets received out-of-order " + thisSequenceNumber + " " + lastSequenceNum);
			lastSequenceNum = thisSequenceNumber;
		}

		byte[] payload;
		if (rest.length == 0) {
			payload = Arrays.copyOfRange(initial.data(), 0, initial.messageLength());
		} else {
			payload = new byte[initial.messageLength()];
			System.arraycopy(initial.data(), 0, payload, 0, initial.data().length);
			int offset = initial.data().length;
			int remaining = initial.messageLength() - offset;
			for (ContinuationPacket packet : rest) {
				int usableLength = packet.data().length;
				if (remaining < usableLength) {
					usableLength = remaining;
				}
				System.arraycopy(packet.data(), 0, payload, offset, usableLength);
				offset += usableLength;
				remaining -= usableLength;
			}
		}
		return ImmutableRawMessage.of(initial.channelId(), initial.command(), payload);
	}

	@Value.Parameter
	public abstract ChannelId channelId();
	
	@Value.Parameter
	public abstract HidCommand command();
	
	@Value.Parameter
	public abstract byte[] payload();
}
