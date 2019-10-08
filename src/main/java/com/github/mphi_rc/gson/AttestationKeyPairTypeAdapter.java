package com.github.mphi_rc.gson;

import java.lang.reflect.Type;

import com.github.mphi_rc.fido2.authenticator.crypto.Algorithm;
import com.github.mphi_rc.fido2.authenticator.crypto.AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.Ed25519AttestationKeyPair;
import com.github.mphi_rc.fido2.authenticator.crypto.P256AttestationKeyPair;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

public class AttestationKeyPairTypeAdapter implements JsonSerializer<AttestationKeyPair>, JsonDeserializer<AttestationKeyPair> {

	@Override
	public AttestationKeyPair deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context)
			throws JsonParseException {
		String namedCurve = json.getAsJsonObject().get("namedCurve").getAsString();
		if (namedCurve.equals(Algorithm.P256_ECDSA.toString())) {
			return context.deserialize(json, P256AttestationKeyPair.class);
		} else if(namedCurve.equals(Algorithm.Ed25519.toString())) {
			return context.deserialize(json, Ed25519AttestationKeyPair.class);
		}
		throw new JsonParseException("Unknown AttestationKeyPair implementation");
	}

	@Override
	public JsonElement serialize(AttestationKeyPair src, Type typeOfSrc, JsonSerializationContext context) {
		if (src instanceof P256AttestationKeyPair) {
			return context.serialize((P256AttestationKeyPair) src);
		} else if (src instanceof Ed25519AttestationKeyPair) {
			return context.serialize((Ed25519AttestationKeyPair) src);
		}
		throw new RuntimeException("Unknown AttestationKeyPair implementation");
	}
}
