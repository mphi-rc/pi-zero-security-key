package com.github.mphi_rc.fido2.authenticator.user.adafruit;

import com.pi4j.io.gpio.event.GpioPinDigitalStateChangeEvent;
import com.pi4j.io.gpio.event.GpioPinListenerDigital;

class ButtonListener implements GpioPinListenerDigital {

	private final UserVerifierStateMachine stateMachine;

	public ButtonListener(UserVerifierStateMachine stateMachine) {
		this.stateMachine = stateMachine;
	}

	@Override
	public void handleGpioPinDigitalStateChangeEvent(GpioPinDigitalStateChangeEvent event) {
		if (event.getState().isLow()) { // on down press
			switch(event.getPin().getPin().getAddress()) {
			case 21:
				stateMachine.setDecision(UserDecision.ALLOW);
				break;
			case 22:
				stateMachine.setDecision(UserDecision.DENY);
				break;
			}
		}
	}
}