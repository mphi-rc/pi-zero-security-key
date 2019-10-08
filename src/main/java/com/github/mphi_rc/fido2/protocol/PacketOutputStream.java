package com.github.mphi_rc.fido2.protocol;

import java.io.DataOutputStream;
import java.io.IOException;
import java.util.function.Consumer;

import com.github.mphi_rc.fido2.protocol.usbhid.Packet;

public class PacketOutputStream implements Consumer<Packet>, AutoCloseable {

	private final DataOutputStream outputStream;
	
	public PacketOutputStream(DataOutputStream outputStream) {
		this.outputStream = outputStream;
	}
	
	@Override
	public void accept(Packet packet) {
		try {
			outputStream.write(packet.rawPayload());
			outputStream.flush();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void close() {
		try {
			outputStream.close();
		} catch (IOException e) {
			// ignore
		}
	}
	
}
