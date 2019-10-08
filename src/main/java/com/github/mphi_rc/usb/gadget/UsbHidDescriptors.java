package com.github.mphi_rc.usb.gadget;

public class UsbHidDescriptors {
	
	private UsbHidDescriptors() { }

	public static final byte[] FIDO2 = {
			(byte) 0x06, (byte) 0xD0, (byte) 0xF1,	/*  Usage Page (F1D0h),         */
			(byte) 0x09, (byte) 0x01,				/*  Usage (01h),                */
			(byte) 0xA1, (byte) 0x01,				/*  Collection (Application),   */
			(byte) 0x09, (byte) 0x20,				/*      Usage (20h),            */
			(byte) 0x15, (byte) 0x00,				/*      Logical Minimum (0),    */
			(byte) 0x26, (byte) 0xFF, (byte) 0x00,	/*      Logical Maximum (255),  */
			(byte) 0x75, (byte) 0x08,				/*      Report Size (8),        */
			(byte) 0x95, (byte) 0x40,				/*      Report Count (64),      */
			(byte) 0x81, (byte) 0x02,				/*      Input (Variable),       */
			(byte) 0x09, (byte) 0x21,				/*      Usage (21h),            */
			(byte) 0x15, (byte) 0x00,				/*      Logical Minimum (0),    */
			(byte) 0x26, (byte) 0xFF, (byte) 0x00,	/*      Logical Maximum (255),  */
			(byte) 0x75, (byte) 0x08,				/*      Report Size (8),        */
			(byte) 0x95, (byte) 0x40,				/*      Report Count (64),      */
			(byte) 0x91, (byte) 0x02,				/*      Output (Variable),      */
			(byte) 0xC0};							/*  End Collection              */
}
