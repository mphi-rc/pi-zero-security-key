package com.github.mphi_rc.fido2.protocol;

import java.util.ArrayList;
import java.util.Optional;

import com.github.mphi_rc.fido2.protocol.usbhid.ContinuationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.InitializationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;

public class PacketBuffer {
	
	private InitializationPacket firstFragment;
	private ArrayList<ContinuationPacket> nextFragments;
	private int remainingBytes;
	
	public PacketBuffer(InitializationPacket firstFragment) {
		this.firstFragment = firstFragment;
		this.nextFragments = new ArrayList<>();
		this.remainingBytes = firstFragment.messageLength() - firstFragment.data().length;
	}
	
	public void enqueueFragment(ContinuationPacket nextFragment) {
		this.nextFragments.add(nextFragment);
		this.remainingBytes -= nextFragment.data().length;
	}
	
	public Optional<RawMessage> constructIfPossible() {
		if (remainingBytes >= 0) {
			return Optional.empty();
		}
		ContinuationPacket[] rest = new ContinuationPacket[nextFragments.size()];
		RawMessage message = RawMessage.from(firstFragment, nextFragments.toArray(rest));
		return Optional.of(message);
	}
}
