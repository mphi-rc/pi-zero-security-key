package com.github.mphi_rc.fido2.protocol.ctap2.pin;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.util.List;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.authenticator.PinState;
import com.github.mphi_rc.fido2.authenticator.Result;
import com.github.mphi_rc.fido2.authenticator.crypto.CoseKeyConstants;
import com.github.mphi_rc.fido2.protocol.ctap2.Ctap2ResponseCode;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.NegativeInteger;
import co.nstant.in.cbor.model.UnsignedInteger;

public class PinRequestHandler {

	private static final Logger log = LoggerFactory.getLogger(PinRequestHandler.class);
	private static final int KEY_AGREEMENT_KEY = 0x01;
	private static final int PIN_TOKEN_KEY = 0x02;
	private static final int RETRIES_KEY = 0x03;

	private PinState pinState;

	public PinRequestHandler(PinState pinState) {
		this.pinState = pinState;
	}

	public List<DataItem> getRetries() {
		return new CborBuilder().addMap()
				.put(RETRIES_KEY, pinState.getCountRemainingPinAttempts())
				.end()
				.build();
	}

	public List<DataItem> getKeyAgreementKey() {
		try {
			PublicKey key = pinState.getKeyAgreementKey();
			ECPublicKeyParameters params = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(key);
			ECFieldElement x = params.getQ().getXCoord();
			ECFieldElement y = params.getQ().getYCoord();
			List<DataItem> coseKey = new CborBuilder()
					.addMap()
					.put(CoseKeyConstants.KEY_TYPE, CoseKeyConstants.ELLIPTIC_CURVE_X_Y_COORDS)
					.put(CoseKeyConstants.ALGORITHM, CoseKeyConstants.ECDH_ES_HKDF_256)
					.put(CoseKeyConstants.CURVE, CoseKeyConstants.P256)
					.put(CoseKeyConstants.X_COORDINATE, x.getEncoded())
					.put(CoseKeyConstants.Y_COORDINATE, y.getEncoded())
					.end()
					.build();
			log.trace("P-256 public key serialized to COSE key {}", coseKey);

			return new CborBuilder().addMap()
					.put(new UnsignedInteger(KEY_AGREEMENT_KEY), coseKey.get(0))
					.end()
					.build();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public Ctap2ResponseCode setPin(Map hostCoseKey, byte[] encryptedNewPin, byte[] pinAuth) {
		log.trace("recevied setPin request");
		if (pinState.isPinSet()) {
			return Ctap2ResponseCode.PIN_AUTH_INVALID;
		}
		PublicKey hostKey = parseCoseKey(hostCoseKey);
		return pinState.setNewPin(hostKey, encryptedNewPin, pinAuth);
	}

	public Ctap2ResponseCode changePin(Map hostCoseKey, byte[] encryptedPinHash, byte[] encryptedNewPin, byte[] pinAuth) {
		log.trace("recevied changePin request");
		if (pinState.getCountRemainingPinAttempts() == 0) {
			return Ctap2ResponseCode.PIN_BLOCKED;
		}
		PublicKey hostKey = parseCoseKey(hostCoseKey);
		return pinState.setPin(hostKey, encryptedNewPin, encryptedPinHash, pinAuth);
	}

	public Result<List<DataItem>, Ctap2ResponseCode> getPinToken(Map hostCoseKey, byte[] encryptedPinHash) {
		log.trace("recevied getPinToken request");
		if (pinState.getCountRemainingPinAttempts() == 0) {
			return Result.err(Ctap2ResponseCode.PIN_BLOCKED);
		}
		PublicKey hostKey = parseCoseKey(hostCoseKey);
		return pinState.getPinTokenEncrypted(hostKey, encryptedPinHash)
				.handleError(err -> Result.<List<DataItem>, Ctap2ResponseCode>err(err))
				.elseGet(bytes -> {
					List<DataItem> pinTokenCbor = new CborBuilder().addMap()
							.put(PIN_TOKEN_KEY, bytes)
							.end()
							.build();
					return Result.ok(pinTokenCbor);
				});
	}

	private PublicKey parseCoseKey(Map coseKey) {
		try {
			ByteString x = (ByteString) coseKey.get(new NegativeInteger(CoseKeyConstants.X_COORDINATE));
			ByteString y = (ByteString) coseKey.get(new NegativeInteger(CoseKeyConstants.Y_COORDINATE));
			BigInteger xInt = BigIntegers.fromUnsignedByteArray(x.getBytes());
			BigInteger yInt = BigIntegers.fromUnsignedByteArray(y.getBytes());

			KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("prime256v1");
			ECPoint point = spec.getCurve().createPoint(xInt, yInt);
			ECPublicKeySpec keySpec = new ECPublicKeySpec(point, spec);
			return kf.generatePublic(keySpec);
		} catch (Exception e) {
			log.error("Error parsing key", e);
			throw new RuntimeException(e);
		}
	}

}
