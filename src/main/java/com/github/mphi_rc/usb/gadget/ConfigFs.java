package com.github.mphi_rc.usb.gadget;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.google.common.io.BaseEncoding;

public class ConfigFs {

	private final Path rootDirectory;

	public static ConfigFs ofDefault() {
		return new ConfigFs(Paths.get("/sys/kernel/config/"));
	}

	private static String byteToHex(byte b) {
		return "0x" + BaseEncoding.base16().lowerCase().encode(new byte[] { b });
	}

	private ConfigFs(Path rootDirectory) {
		this.rootDirectory = rootDirectory;
	}

	public void initialize(UsbHidGadget gadget) throws IOException {
		Path gadgetRoot = getGadgetRoot(gadget.name());
		if (Files.isDirectory(gadgetRoot)) {
			// already exists
			return;
		}

		Files.createDirectories(gadgetRoot);

		writeConfig(gadgetRoot, "idVendor", gadget.vendorId());
		writeConfig(gadgetRoot, "idProduct", gadget.productId());
		writeConfig(gadgetRoot, "bcdDevice", gadget.deviceBcd());
		writeConfig(gadgetRoot, "bcdUSB", gadget.usbVersionBcd());
		writeConfig(gadgetRoot, "bDeviceProtocol", byteToHex(gadget.deviceProtocol()));
		writeConfig(gadgetRoot, "bDeviceSubClass", byteToHex(gadget.deviceSubClass()));
		writeConfig(gadgetRoot, "bMaxPacketSize0", byteToHex(gadget.maxPacketSize()));

		// strings
		Path stringsRoot = gadgetRoot.resolve("strings/0x409/");
		if (Files.notExists(stringsRoot)) {
			Files.createDirectories(stringsRoot);
		}

		writeConfig(stringsRoot, "serialnumber", gadget.serialNumber().orElse(""));
		writeConfig(stringsRoot, "manufacturer", gadget.manufacturerName());
		writeConfig(stringsRoot, "product", gadget.productName());

		// config
		Path configStringRoot = gadgetRoot.resolve("configs/c.1/strings/0x409/");
		if (Files.notExists(configStringRoot)) {
			Files.createDirectories(configStringRoot);
		}
		writeConfig(configStringRoot, "configuration", gadget.configurationName().orElse(""));
		writeConfig(configStringRoot, "../../MaxPower", String.valueOf(gadget.maxPowerMilliamps()));

		// functions		
		Path functionRoot = gadgetRoot.resolve("functions/hid.usb0");
		if (Files.notExists(functionRoot)) {
			Files.createDirectories(functionRoot);
		}
		writeConfig(functionRoot, "protocol", String.valueOf(gadget.hidProtocol()));
		writeConfig(functionRoot, "subclass", String.valueOf(gadget.hidSubClass()));
		writeConfig(functionRoot, "report_length", String.valueOf(gadget.hidReportLength()));
		writeConfig(functionRoot, "report_desc", gadget.hidDescriptor());

		Files.createSymbolicLink(gadgetRoot.resolve("configs/c.1/hid.usb0"),
				gadgetRoot.resolve("functions/hid.usb0"));
	}

	public void attach(UsbHidGadget gadget, UsbDeviceController driver) throws IOException {
		Path gadgetRoot = getGadgetRoot(gadget.name());
		byte[] udcConfig = readConfig(gadgetRoot, "UDC");

		if (new String(udcConfig, StandardCharsets.US_ASCII).trim().isEmpty()) {
			writeConfig(gadgetRoot, "UDC", driver.name());
		}
	}

	public void detach(UsbHidGadget gadget) throws IOException {
		Path gadgetRoot = getGadgetRoot(gadget.name());
		writeConfig(gadgetRoot, "UDC", "");
	}

	public void destroy(UsbHidGadget gadget) throws IOException {
		Path root = getGadgetRoot(gadget.name());
		writeConfig(root, "UDC", "");
		Files.delete(root.resolve("configs/c.1/hid.usb0"));
		Files.delete(root.resolve("configs/c.1/strings/0x409"));
		Files.delete(root.resolve("configs/c.1"));
		Files.delete(root.resolve("strings/0x409"));
		Files.delete(root.resolve("functions/hid.usb0"));
		Files.delete(root);
	}

	private Path getGadgetRoot(String gadgetName) {
		return rootDirectory.resolve("usb_gadget/" + gadgetName);
	}

	private void writeConfig(Path gadgetRoot, String name, byte[] value) throws IOException {
		try (OutputStream out = Files.newOutputStream(gadgetRoot.resolve(name))) {
			out.write(value);
		}
	}

	private byte[] readConfig(Path gadgetRoot, String name) throws IOException {
		return Files.readAllBytes(gadgetRoot.resolve(name));
	}

	private void writeConfig(Path gadgetRoot, String name, String hexValue) throws IOException {
		byte[] value = hexValue.getBytes(StandardCharsets.US_ASCII);
		writeConfig(gadgetRoot, name, value);
	}

}