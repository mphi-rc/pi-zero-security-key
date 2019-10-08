package com.github.mphi_rc.usb.gadget;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.immutables.gson.Gson;
import org.immutables.value.Value;

import com.google.common.base.Preconditions;

@Gson.TypeAdapters
@Value.Immutable
public interface UsbDeviceController {

	static UsbDeviceController raspberryPiZero() {
		return ImmutableUsbDeviceController.of("20980000.usb");
	}

	static UsbDeviceController dummy() {
		return ImmutableUsbDeviceController.of("dummy_udc.0");
	}

	@Value.Parameter
	String name();

	@Value.Check
	default void check() {
		Path udcPath = Paths.get("/sys/class/udc/", name());
		Preconditions.checkState(Files.isDirectory(udcPath), "Chosen USB device controller is unavailable");
	}

}