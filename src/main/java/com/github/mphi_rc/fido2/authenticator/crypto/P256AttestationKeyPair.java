package com.github.mphi_rc.fido2.authenticator.crypto;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.function.Supplier;

import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECFieldElement;
import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;
import com.google.common.base.Suppliers;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;

@Gson.TypeAdapters
@Value.Immutable
public abstract class P256AttestationKeyPair implements AttestationKeyPair {

	private static final Logger log = LoggerFactory.getLogger(P256AttestationKeyPair.class);
	private static final Provider securityProvider = new BouncyCastleProvider();
	private static final String JCE_SIGNATURE_ALGORITHM = "SHA256withECDDSA";
	private static final String JCE_NAMED_CURVE = "P-256";
	private static final String JCE_KEY_ALGORITHM = "EC";

	private Supplier<PrivateKey> jcePrivateKey = Suppliers.memoize(() -> {
		try {
			KeyFactory kf = KeyFactory.getInstance(JCE_KEY_ALGORITHM, securityProvider);
			return kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey()));
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	});
	
	public static P256AttestationKeyPair generate() {
		try {
			log.trace("Generating new P-256 key pair");
			AlgorithmParameters algParam = AlgorithmParameters.getInstance(JCE_KEY_ALGORITHM, securityProvider);
			algParam.init(new ECGenParameterSpec(JCE_NAMED_CURVE));
			ECGenParameterSpec parameterSpec = algParam.getParameterSpec(ECGenParameterSpec.class);

			KeyPairGenerator generator = KeyPairGenerator.getInstance(JCE_KEY_ALGORITHM, securityProvider);
			generator.initialize(parameterSpec);
			KeyPair keyPair = generator.generateKeyPair();

			PrivateKey privateKey = keyPair.getPrivate();
			BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
			publicKey.setPointFormat("COMPRESSED");

			return ImmutableP256AttestationKeyPair.builder()
					.privateKey(privateKey.getEncoded())
					.publicKey(publicKey.getEncoded())
					.build();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Value.Derived
	@Override
	public Algorithm namedCurve() {
		return Algorithm.P256_ECDSA;
	}

	@Override
	public abstract byte[] publicKey();

	@Override
	public abstract byte[] privateKey();

	@Value.Lazy
	@Override
	public List<DataItem> getCborEncodedPublicKey() {
		try {
			KeyFactory kf = KeyFactory.getInstance(JCE_KEY_ALGORITHM, securityProvider);
			PublicKey key = kf.generatePublic(new X509EncodedKeySpec(publicKey()));

			ECPublicKeyParameters params = (ECPublicKeyParameters) ECUtil.generatePublicKeyParameter(key);
			ECFieldElement x = params.getQ().getXCoord();
			ECFieldElement y = params.getQ().getYCoord();
			List<DataItem> coseKey = new CborBuilder()
					.addMap()
					.put(CoseKeyConstants.KEY_TYPE, CoseKeyConstants.ELLIPTIC_CURVE_X_Y_COORDS)
					.put(CoseKeyConstants.ALGORITHM, CoseKeyConstants.ES256)
					.put(CoseKeyConstants.CURVE, CoseKeyConstants.P256)
					.put(CoseKeyConstants.X_COORDINATE, x.getEncoded())
					.put(CoseKeyConstants.Y_COORDINATE, y.getEncoded())
					.end()
					.build();
			log.trace("P-256 public key serialized to COSE key {}", coseKey);
			return coseKey;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] sign(AuthenticatorData authData, byte[] clientDataHash) {
		log.trace("Creating ECDSA signature for authenticator data {} and client data hash {}", authData, clientDataHash);
		try {
			Signature signature = Signature.getInstance(JCE_SIGNATURE_ALGORITHM, securityProvider);
			signature.initSign(jcePrivateKey.get());
			signature.update(authData.asBytes());
			signature.update(clientDataHash);
			return signature.sign();
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}
}
