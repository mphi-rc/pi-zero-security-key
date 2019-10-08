package com.github.mphi_rc.fido2.authenticator.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import org.immutables.gson.Gson;
import org.immutables.value.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.mphi_rc.fido2.protocol.ctap2.AuthenticatorData;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;

@Gson.TypeAdapters
@Value.Immutable
public abstract class Ed25519AttestationKeyPair implements AttestationKeyPair {

	private static final Logger log = LoggerFactory.getLogger(Ed25519AttestationKeyPair.class);
	
	public static Ed25519AttestationKeyPair generate() {
		log.trace("Generating new Ed25519 key pair");
		try {
			java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("EdDSA", new EdDSASecurityProvider());
			KeyPair keyPair = gen.generateKeyPair();
			return ImmutableEd25519AttestationKeyPair.builder()
					.privateKey(keyPair.getPrivate().getEncoded())
					.publicKey(keyPair.getPublic().getEncoded())
					.build();
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	@Value.Derived
	@Override
	public Algorithm namedCurve() {
		return Algorithm.Ed25519;
	}

	@Override
	public abstract byte[] publicKey();

	@Override
	public abstract byte[] privateKey();

	@Value.Lazy
	@Override
	public List<DataItem> getCborEncodedPublicKey() {
		try {
			X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey());
			byte[] publicKey = new EdDSAPublicKey(spec).getAbyte();
			List<DataItem> coseKey = new CborBuilder()
					.addMap()
					.put(CoseKeyConstants.KEY_TYPE, CoseKeyConstants.OCTET_KEY_PAIR)
					.put(CoseKeyConstants.ALGORITHM, CoseKeyConstants.EDDSA)
					.put(CoseKeyConstants.CURVE, CoseKeyConstants.ED25519)
					.put(CoseKeyConstants.X_COORDINATE, publicKey)
					.end()
					.build();
			log.trace("Ed25519 public key serialized to COSE key {}", coseKey);
			return coseKey;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] sign(AuthenticatorData authData, byte[] clientDataHash) {
		log.trace("Creating raw EdDSA signature for authenticator data {} and client data hash {}", authData, clientDataHash);
		try {
			Signature signature = Signature.getInstance("NONEwithEdDSA", new EdDSASecurityProvider());
			EdDSAPrivateKey privateKey = new EdDSAPrivateKey(new PKCS8EncodedKeySpec(privateKey()));
			signature.initSign(privateKey);
			signature.update(authData.asBytes());
			signature.update(clientDataHash);
			return signature.sign();
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}
}
