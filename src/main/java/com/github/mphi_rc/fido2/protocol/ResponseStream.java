package com.github.mphi_rc.fido2.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.protocol.usbhid.ImmutablePacket;
import com.github.mphi_rc.fido2.protocol.usbhid.Packet;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;
import com.google.common.primitives.UnsignedInteger;

public class ResponseStream implements Consumer<RawMessage>, AutoCloseable {

	private static final Logger log = LoggerFactory.getLogger(ResponseStream.class);
	private static final int INIT_HEADER_SIZE = 7;
	private static final int CONT_HEADER_SIZE = 5;

	private final PacketOutputStream outputStream;
	private final int usbPacketSizeBytes;
	private final int initSpace;
	private final int contSpace;

	public ResponseStream(PacketOutputStream inputStream) {
		this.outputStream = inputStream;
		this.usbPacketSizeBytes = 64;
		this.initSpace = usbPacketSizeBytes - INIT_HEADER_SIZE;
		this.contSpace = usbPacketSizeBytes - CONT_HEADER_SIZE;
	}

	@Override
	public void close() {
		outputStream.close();
	}

	@Override
	public void accept(RawMessage message) {
		log.trace("Sending response {}", message);

		for (Packet packet : serializeToPackets(message)) {
			outputStream.accept(packet);
		}
	}

	private Packet serializeToInitPacket(RawMessage m) {
		try {
			byte[] channel = m.channelId().id();
			byte command = m.command().asByte();
			byte[] payload = m.payload();
			int lengthHigh = payload.length & 0xFF00;
			int lengthLow = payload.length & 0x00FF;
			int payloadReadLength = Math.min(payload.length, initSpace);

			ByteArrayOutputStream packet = new ByteArrayOutputStream();
			packet.write(channel);
			packet.write(command);
			packet.write(lengthHigh);
			packet.write(lengthLow);
			packet.write(payload, 0, payloadReadLength);

			while (usbPacketSizeBytes < packet.size()) {
				packet.write(0);
			}
			return ImmutablePacket.of(packet.toByteArray());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private Packet serializeToContPacket(RawMessage m, int sequenceNumber, int packetPayloadLength) {
		try {
			int payloadOffset = initSpace + sequenceNumber * contSpace;
			byte[] channel = m.channelId().id();
			byte seq = UnsignedInteger.valueOf(sequenceNumber).byteValue();
			byte[] payload = m.payload();

			ByteArrayOutputStream packet = new ByteArrayOutputStream();
			packet.write(channel);
			packet.write(seq);
			packet.write(payload, payloadOffset, packetPayloadLength);

			while (usbPacketSizeBytes < packet.size()) {
				packet.write(0);
			}
			return ImmutablePacket.of(packet.toByteArray());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private int numPacketsRequired(int payloadSize) {
		if (initSpace >= payloadSize) {
			return 1;
		}
		int remainingPayloadLength = payloadSize - initSpace;
		int numPackets = 1 + (remainingPayloadLength / contSpace);
		if (remainingPayloadLength % contSpace != 0) {
			numPackets++;
		}
		return numPackets;
	}

	private List<Packet> serializeToPackets(RawMessage m) {
		int bytesRemaining = m.payload().length;
		int numPackets = numPacketsRequired(bytesRemaining);

		List<Packet> packets = new ArrayList<>(numPackets);
		packets.add(serializeToInitPacket(m));
		bytesRemaining -= initSpace;

		for (int p = 0; p < numPackets - 1; p++) {
			int packetPayloadLength = Math.min(bytesRemaining, contSpace); 
			packets.add(serializeToContPacket(m, p, packetPayloadLength));
			bytesRemaining -= contSpace;
		}
		return packets;
	}

}
