package com.github.mphi_rc.fido2.protocol.usbhid.command;

import org.immutables.value.Value;

import com.github.mphi_rc.fido2.protocol.usbhid.HidCommand;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import com.github.mphi_rc.fido2.protocol.usbhid.command.ImmutableInitRequestPayload;
import com.google.common.base.Preconditions;

@Value.Immutable
public interface InitRequestPayload {

	public static InitRequestPayload from(RawMessage message) {
		Preconditions.checkArgument(message.command().equals(HidCommand.INIT), "must be message with an INIT command");
		return ImmutableInitRequestPayload.of(message.payload());
	}

	@Value.Parameter
	byte[] nonce();
}
