package com.github.mphi_rc.fido2.authenticator.user.adafruit;

enum UserDecision {

	TIMEOUT("DENIED (timed out)"),
	ALLOW("ALLOWED"),
	DENY("DENIED");

	private String text;

	UserDecision(String text) {
		this.text = text;
	}

	String text() {
		return text;
	}
}