package com.github.mphi_rc.fido2.authenticator.user.adafruit;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.ondryaso.ssd1306.Display;

class UserVerifierStateMachine {

	private static final Logger log = LoggerFactory.getLogger(UserVerifierStateMachine.class);

	private Optional<UserDecision> decision;
	private Optional<Operation> ongoingOperation;
	private int secondsToTimeout;

	public UserVerifierStateMachine() {
		this.decision = Optional.empty();
		this.ongoingOperation = Optional.empty();
		this.secondsToTimeout = 5;
	}

	void setDecision(UserDecision d) {
		if (!ongoingOperation.isPresent()) {
			log.debug("There's no ongoing operation");
			return;
		}

		if (decision.isPresent()) {
			log.debug("There's already a decision");
			return;
		}
		decision = Optional.of(d);
	}

	UserDecision consumeDecision() {
		try {
			return decision.get();
		} finally {
			decision = Optional.empty();
		}
	}

	void start(Operation operation) {
		if (ongoingOperation.isPresent()) {
			throw new RuntimeException("Ongoing operation already exists");
		}
		ongoingOperation = Optional.of(operation);
	}

	void advanceTimeByASecond() {
		if (secondsToTimeout == 0) {
			return;
		}

		if (decision.isPresent()) {
			secondsToTimeout = 0;
			return;
		}

		secondsToTimeout--;

		if (secondsToTimeout == 0 && !decision.isPresent()) {
			decision = Optional.of(UserDecision.TIMEOUT);
		}
	}

	void reset(Display display) {
		decision = Optional.empty();
		ongoingOperation = Optional.empty();
		secondsToTimeout = 5;

		Graphics2D gfx = display.getGraphics();
		gfx.clearRect(0, 0, 128, 64);
		display.displayImage();
	}

	void renderDisplay(Display display, String origin) {
		Graphics2D gfx = display.getGraphics();
		gfx.clearRect(0, 0, 128, 64);

		if (!ongoingOperation.isPresent()) {
			return;
		}
		gfx.setColor(Color.WHITE);
		gfx.setFont(new Font("Monospaced", Font.PLAIN, 10));

		if (ongoingOperation.get().equals(Operation.REGISTER)) {
			gfx.drawString("Register with", 0, 10);
		} else {
			gfx.drawString("Authenticate to", 0, 10);
		}
		gfx.drawString(origin + "?", 0, 25);

		if (secondsToTimeout != 0) {
			display.getGraphics().drawString(String.valueOf(secondsToTimeout), 120, 64);
		}
		if (decision.isPresent()) {
			gfx.drawString(decision.get().text(), 0, 53);
		}
		display.displayImage();
	}
}