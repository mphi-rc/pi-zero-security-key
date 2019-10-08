package com.github.mphi_rc.fido2;

import com.github.mphi_rc.usb.gadget.ConfigFs;
import com.github.mphi_rc.usb.gadget.ImmutableUsbHidGadget;
import com.github.mphi_rc.usb.gadget.UsbHidDescriptors;
import com.github.mphi_rc.usb.gadget.UsbHidGadget;

public class Fido2AuthenticatorCli {

	private Fido2AuthenticatorCli() {}

	public static void main(String[] args) throws Exception {

		ConfigurationFile config = ConfigurationFile.defaultPath();
		config.persistToDiskAsync();

		UsbHidGadget fido2Gadget = ImmutableUsbHidGadget.builder()
				.name(config.usbGadgetName())
				.manufacturerName("Acme")
				.productName("FIDO2 Security Key")
				.vendorId("0x1050")
				.productId("0x0402")
				.deviceBcd("0x0512")
				.hidDescriptor(UsbHidDescriptors.FIDO2)
				.hidReportLength(64)
				.build();

		ConfigFs configFs = ConfigFs.ofDefault();
		configFs.initialize(fido2Gadget);
		configFs.attach(fido2Gadget, config.usbDeviceController());

		Fido2Authenticator authenticator = new Fido2Authenticator(config);
		authenticator.start();
	}
}
