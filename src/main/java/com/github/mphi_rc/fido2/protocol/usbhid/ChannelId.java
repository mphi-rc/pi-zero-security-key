package com.github.mphi_rc.fido2.protocol.usbhid;

import java.security.SecureRandom;

import org.immutables.value.Value;
import org.immutables.value.Value.Parameter;

import com.google.common.base.Preconditions;

@Value.Immutable
public abstract class ChannelId {
	
	public static ChannelId broadcast() {
		return ImmutableChannelId.of(new byte[] {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF});
	}
	
	public static ChannelId random() {
		SecureRandom r = new SecureRandom();
		byte[] id = new byte[4];
		r.nextBytes(id);
		return ImmutableChannelId.of(id);
	}
	
	@Parameter
	public abstract byte[] id();
	
	@Value.Check
	protected void check() {
		Preconditions.checkArgument(id().length == 4, "id must be a 4-byte array");
	}
}
