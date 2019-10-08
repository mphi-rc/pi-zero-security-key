package com.github.mphi_rc.fido2;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.authenticator.Credential;
import com.github.mphi_rc.fido2.authenticator.GsonAdaptersCredential;
import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.GsonAdaptersEd25519AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.GsonAdaptersP256AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.user.AlwaysAllowUserVerifier;
import com.github.mphi_rc.fido2.authenticator.user.UserVerifier;
import com.github.mphi_rc.fido2.authenticator.user.adafruit.Adafruit3531UserVerifier;
import com.github.mphi_rc.gson.AttestationKeyPairTypeAdapter;
import com.github.mphi_rc.gson.Base64TypeAdapter;
import com.github.mphi_rc.gson.MillisTypeAdapter;
import com.github.mphi_rc.usb.gadget.GsonAdaptersUsbDeviceController;
import com.github.mphi_rc.usb.gadget.UsbDeviceController;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class ConfigurationFile implements Configuration {

	private final static Logger log = LoggerFactory.getLogger(ConfigurationFile.class);

	private final ExecutorService executorService;
	private final Gson gson;
	private final Path configFile;
	private Configuration config;

	public static ConfigurationFile defaultPath() {
		return new ConfigurationFile(Paths.get("config.json"));
	}

	public ConfigurationFile(Path configFile) {
		this.gson = new GsonBuilder()
				.setPrettyPrinting()
				.registerTypeAdapterFactory(new GsonAdaptersConfiguration())
				.registerTypeAdapterFactory(new GsonAdaptersUsbDeviceController())
				.registerTypeAdapterFactory(new GsonAdaptersCredential())
				.registerTypeAdapterFactory(new GsonAdaptersEd25519AttestationKeyPair())
				.registerTypeAdapterFactory(new GsonAdaptersP256AttestationKeyPair())
				.registerTypeAdapter(AttestationKeyPair.class, new AttestationKeyPairTypeAdapter())
				.registerTypeAdapter(byte[].class, new Base64TypeAdapter())
				.registerTypeAdapter(Instant.class, new MillisTypeAdapter())
				.create();
		this.configFile = configFile;
		this.executorService = Executors.newFixedThreadPool(1);
		this.config = readFromDisk();
	}

	public UserVerifier userVerifier() {
		if (config.enableBonnet()) {
			try {
				return new Adafruit3531UserVerifier();
			} catch (Exception e) {
				log.error("Cannot instantiate Adafruit Bonnet hardware", e);
			}
		}
		return new AlwaysAllowUserVerifier();
	}

	public void updatePinHash(byte[] pinHash) {
		config = ImmutableConfiguration.builder()
				.from(config)
				.pinHash(Optional.of(pinHash))
				.build();
		persistToDiskAsync();
	}

	public void addCredential(Credential credential) {
		config = ImmutableConfiguration.builder()
				.from(config)
				.addCredentials(credential)
				.build();
		persistToDiskAsync();
	}

	public void updateAllStoredCredentials(List<Credential> credentials) {
		config = ImmutableConfiguration.builder()
				.from(config)
				.credentials(credentials)
				.build();
		persistToDiskAsync();
	}

	public byte[] getAaguid() {
		ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
		bb.putLong(id().getMostSignificantBits());
		bb.putLong(id().getLeastSignificantBits());
		return bb.array();
	}

	@Override
	public UsbDeviceController usbDeviceController() {
		return config.usbDeviceController();
	}

	@Override
	public List<Credential> credentials() {
		return config.credentials();
	}

	@Override
	public List<Algorithm> enabledAlgorithms() {
		return config.enabledAlgorithms();
	}

	@Override
	public UUID id() {
		return config.id();
	}

	public Optional<byte[]> pinHash() {
		return config.pinHash();
	}

	@Override
	public boolean enableBonnet() {
		return config.enableBonnet();
	}

	@Override
	public String usbGadgetDevicePath() {
		return config.usbGadgetDevicePath();
	}

	@Override
	public String usbGadgetName() {
		return config.usbGadgetName();
	}

	public void persistToDiskAsync() {
		executorService.submit(() -> {
			synchronized (configFile) {
				String json = gson.toJson(config);
				try {
					Files.write(configFile, json.getBytes(StandardCharsets.UTF_8));
				} catch (IOException e) {
					log.error("Unable to write configuration state", e);
				}
			}
		});
	}

	private Configuration readFromDisk() {
		if (Files.exists(configFile)) {
			byte[] bytes;
			try {
				bytes = Files.readAllBytes(configFile);
				String json = new String(bytes, StandardCharsets.UTF_8);
				return gson.fromJson(json, Configuration.class);
			} catch (IOException e) {
				log.error("Unable to read configuration state", e);
				throw new RuntimeException(e);
			}
		}
		return ImmutableConfiguration.builder().build();
	}

}
