package com.tujuhsembilan.example.repository;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;

public class SessionRepository {
    // <sessionId, jwk>
    private static Map<String, ECKey> sessionMap = new HashMap<>();

    public static String createSession() {
        try {
            String sessionId = UUID.randomUUID().toString();

            ECKey jwk = new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.ENCRYPTION)
                    .keyID(sessionId)
                    .generate();

            sessionMap.put(sessionId, jwk);
            return sessionId;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ECKey getSession(String sessionId) {
        return sessionMap.get(sessionId);
    }

    public static String createSession(String sessionId, String JWE) {
        try {
            ECKey jwk = sessionMap.get(sessionId);

            // decrypt JWE and get client's public key and create encrypter
            ECDHEncrypter encrypter = new ECDHEncrypter(ECKey.parse(JWE));

            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM).build(),
                    new Payload(jwk.toPublicJWK().toJSONString()));

            // encrypt jwk with client's public key
            jweObject.encrypt(encrypter);

            // save the jwk to sessionMap
            // sessionMap.put(id, jwk);

            return jweObject.serialize();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
