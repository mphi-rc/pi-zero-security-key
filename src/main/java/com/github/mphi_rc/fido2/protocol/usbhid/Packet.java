package com.github.mphi_rc.fido2.protocol.usbhid;

import java.util.Arrays;
import java.util.BitSet;
import java.util.Optional;

import org.immutables.value.Value;

@Value.Immutable
public abstract class Packet {
	
	@Value.Parameter
	public abstract byte[] rawPayload();
	
	@Value.Derived
	public ChannelId channelId() {
		byte[] bytes = Arrays.copyOfRange(rawPayload(), 0, 4);
		return ImmutableChannelId.of(bytes);
	}
	
	public Optional<InitializationPacket> asInitializationPacket() {
		return isInitializationPacket() ? Optional.of(InitializationPacket.from(this)) : Optional.empty();
	}
	
	public Optional<ContinuationPacket> asContinuationPacket() {
		return isInitializationPacket() ? Optional.empty() : Optional.of(ContinuationPacket.from(this));
	}

	private boolean isInitializationPacket() {
		byte[] distinguishing = Arrays.copyOfRange(rawPayload(), 4, 5);
		BitSet flags = BitSet.valueOf(distinguishing);
		return flags.get(7);
	}
}
