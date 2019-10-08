package com.github.mphi_rc.fido2.authenticator.user.adafruit;

import static com.pi4j.io.gpio.PinPullResistance.PULL_UP;
import static com.pi4j.io.gpio.RaspiPin.GPIO_04;
import static com.pi4j.io.gpio.RaspiPin.GPIO_21;
import static com.pi4j.io.gpio.RaspiPin.GPIO_22;
import static com.pi4j.io.i2c.I2CBus.BUS_1;

import java.util.Arrays;

import com.github.mphi_rc.fido2.authenticator.user.UserVerifier;
import com.pi4j.io.gpio.GpioFactory;
import com.pi4j.io.gpio.GpioPinDigitalInput;
import com.pi4j.io.gpio.Pin;
import com.pi4j.io.i2c.I2CFactory;

import eu.ondryaso.ssd1306.Display;

public class Adafruit3531UserVerifier implements UserVerifier {

	private final Display display;
	private final UserVerifierStateMachine stateMachine;

	public Adafruit3531UserVerifier() throws Exception {
		this.stateMachine = new UserVerifierStateMachine();
		this.display = new Display(128, 64, GpioFactory.getInstance(), I2CFactory.getInstance(BUS_1), 0x3c, GPIO_04);
		configureButtons();
		display.begin();
	}

	private void configureButtons() {
		ButtonListener listener = new ButtonListener(stateMachine);
		for (Pin pin : Arrays.asList(GPIO_21, GPIO_22)) {
			GpioPinDigitalInput input = GpioFactory.getInstance().provisionDigitalInputPin(pin, PULL_UP);
			input.addListener(listener);
		}
	}

	private boolean isApproved(String relayingPartyId, Operation operation) {
		synchronized (stateMachine) {
			try {
				stateMachine.start(operation);

				stateMachine.renderDisplay(display, relayingPartyId);
				for (int second = 0; second < 5; second++) {
					for (int crank = 0; crank < 10; crank++) {
						stateMachine.renderDisplay(display, relayingPartyId);
						Thread.sleep(100);
					}
					stateMachine.advanceTimeByASecond();
				}
				stateMachine.renderDisplay(display, relayingPartyId);

			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			try {
				UserDecision decision = stateMachine.consumeDecision();
				return decision.equals(UserDecision.ALLOW);
			} finally {
				stateMachine.reset(display);
			}
		}
	}

	@Override
	public boolean isRegistrationApproved(String relayingPartyId) {
		return isApproved(relayingPartyId, Operation.REGISTER);
	}

	@Override
	public boolean isAuthenticationApproved(String relayingPartyId) {
		return isApproved(relayingPartyId, Operation.AUTHENTICATE);
	}

}
