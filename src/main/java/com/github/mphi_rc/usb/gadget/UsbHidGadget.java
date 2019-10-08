package com.github.mphi_rc.usb.gadget;

import java.util.Optional;

import org.immutables.value.Value;

@Value.Immutable
public abstract class UsbHidGadget {

	private static final String USB_2_0 = "0x0200";

	abstract String name();

	abstract Optional<String> serialNumber();

	abstract String manufacturerName();

	abstract String productName();
	
	abstract Optional<String> configurationName();

	abstract String vendorId();

	abstract String productId();

	abstract String deviceBcd();

	abstract byte[] hidDescriptor();

	abstract int hidReportLength();

	@Value.Default
	public int hidProtocol() {
		return 0;
	}
	
	@Value.Default
	public int hidSubClass() {
		return 0;
	}
	
	@Value.Default
	public byte deviceProtocol() {
		return 0;
	}

	@Value.Default
	public byte deviceSubClass() {
		return 0;
	}

	@Value.Default
	public byte maxPacketSize() {
		return 8;
	}

	@Value.Default
	public String usbVersionBcd() {
		return USB_2_0;
	}

	@Value.Default
	public int maxPowerMilliamps() {
		return 30;
	}
	
}
