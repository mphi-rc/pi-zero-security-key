package com.github.mphi_rc.fido2.authenticator.crypto;

public class CoseKeyConstants {
	private CoseKeyConstants() {}

	public static final int KEY_TYPE = 1;
	public static final int OCTET_KEY_PAIR = 1;
	public static final int ELLIPTIC_CURVE_X_Y_COORDS = 2;

	public static final int ALGORITHM = 3;
	public static final int EDDSA = -8;
	public static final int ES256 = -7;
	public static final int ECDH_ES_HKDF_256 = -25;

	public static final int CURVE = -1;
	public static final int ED25519 = 6;
	public static final int P256 = 1;

	public static final int X_COORDINATE = -2;
	public static final int Y_COORDINATE = -3;
}

