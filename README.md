# pi-zero-security-key

This is a [FIDO2](https://fidoalliance.org/fido2/) USB security key implementation for the [$5 Raspberry Pi Zero](https://www.raspberrypi.org/products/raspberry-pi-zero/).

You can use it with any FIDO2-compatible browser (Google Chrome or Chromium) and any website supporting FIDO2 [WebAuthN](https://en.wikipedia.org/wiki/WebAuthn).

![](/demo.gif)

It is experimental -- please do not rely on this for use cases with strong security requirements.

## Features

- [Ed25519](https://ed25519.cr.yp.to/) attestation
- [Deterministic ECDSA](https://tools.ietf.org/html/rfc6979) attestation with P-256
- [Adafruit OLED screen and button](https://www.adafruit.com/product/3531) support _(optional)_
- PIN protocol support _(optional)_
- Simple backup and restore: a single file is used for all state
- FIDO2 is supported, but U2F is not

## Usage

Download [the latest release](https://github.com/mphi-rc/pi-zero-security-key/releases), then run `java -jar pi-zero-security-key.jar` with superuser privileges.

If you prefer to build from source, you must checkout [pi-ssd1306-java](https://github.com/mphi-rc/pi-ssd1306-java) and run `./gradlew publishToMavenLocal`. Then, to build, run `./gradlew shadowJar` in this repo.

Note that your kernel must be compiled with ConfigFS USB gadget support. [Raspbian](https://www.raspberrypi.org/downloads/raspbian/) appears to support this by default.

## Configuration

All state is stored in `config.json`, which is created on first run. Common options:

| Option | Type | Description |
| --- | --- | --- |
| `enabledAlgorithms` | string array | A list of attestation algorithms, ordered from most to least preferred. Valid values are `Ed25519` and `P256_ECDSA`. |
| `enableBonnet` | boolean | Whether to expect button presses from, and display auth/register status using, an [Adafruit OLED Bonnet](https://www.adafruit.com/product/3531) |
