package com.github.mphi_rc.fido2.authenticator.crypto;

public enum Algorithm {
	
	P256_ECDSA(CoseKeyConstants.ES256),
	Ed25519(CoseKeyConstants.EDDSA);
	
	private int coseAlgorithm;
	
	Algorithm(int coseAlgorithm) {
		this.coseAlgorithm = coseAlgorithm;
	}
	
	public int getCoseAlgorithmId() {
		return coseAlgorithm;
	}
}
