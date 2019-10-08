package com.github.mphi_rc.fido2.protocol;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.protocol.usbhid.ChannelId;
import com.github.mphi_rc.fido2.protocol.usbhid.ContinuationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.InitializationPacket;
import com.github.mphi_rc.fido2.protocol.usbhid.Packet;
import com.github.mphi_rc.fido2.protocol.usbhid.RawMessage;

public class RequestStream implements AutoCloseable {

	private static final Logger log = LoggerFactory.getLogger(RequestStream.class);
	
	private final PacketInputStream inputStream;
	private final Map<ChannelId, PacketBuffer> bufferByChannel;

	public RequestStream(PacketInputStream inputStream) {
		this.inputStream = inputStream;
		this.bufferByChannel = new HashMap<>();
	}

	@Override
	public void close() {
		inputStream.close();
	}

	public RawMessage readMessage() throws IOException {
		while(true) {
			Optional<RawMessage> maybeBuffered = consumeBufferedMessage();
			if (maybeBuffered.isPresent()) {
				return maybeBuffered.get();
			}
			Packet packet = inputStream.readPacket();

			if (packet.asInitializationPacket().isPresent()) {
				InitializationPacket initPacket = packet.asInitializationPacket().get();
				if (!initPacket.isFragmented()) {
					return RawMessage.from(initPacket);
				}
				bufferByChannel.put(packet.channelId(), new PacketBuffer(initPacket));
			} else {
				ContinuationPacket contPacket = packet.asContinuationPacket().get();
				PacketBuffer buf = bufferByChannel.get(packet.channelId());
				if (Objects.isNull(buf)) {
					log.info("Ignoring spurious continuation packet");
				} else {
					buf.enqueueFragment(contPacket);
				}
			}
		}
	}

	private Optional<RawMessage> consumeBufferedMessage() {
		for (Entry<ChannelId, PacketBuffer> entry : bufferByChannel.entrySet()) {
			PacketBuffer buffer = entry.getValue();
			Optional<RawMessage> maybeQueuedMessage = buffer.constructIfPossible();
			if (maybeQueuedMessage.isPresent()) {
				log.trace("Message {} was reconstructed from several fragments", maybeQueuedMessage.get());
				bufferByChannel.remove(entry.getKey());
				return maybeQueuedMessage;
			}
		}
		return Optional.empty();
	}

}
