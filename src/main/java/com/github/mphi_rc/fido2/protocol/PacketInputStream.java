package com.github.mphi_rc.fido2.protocol;

import java.io.DataInputStream;
import java.io.IOException;

import com.github.mphi_rc.fido2.protocol.usbhid.ImmutablePacket;
import com.github.mphi_rc.fido2.protocol.usbhid.Packet;

public class PacketInputStream implements AutoCloseable {

	private final DataInputStream inputStream;
	private final int usbPacketSizeBytes;

	public PacketInputStream(DataInputStream inputStream) {
		this.inputStream = inputStream;
		this.usbPacketSizeBytes = 64;
	}

	@Override
	public void close() {
		try {
			this.inputStream.close();
		} catch (IOException e) {
			// ignore
		}
	}

	public Packet readPacket() throws IOException {
		byte[] buf = new byte[usbPacketSizeBytes];
		this.inputStream.readFully(buf);
		return ImmutablePacket.of(buf);
	}

}
