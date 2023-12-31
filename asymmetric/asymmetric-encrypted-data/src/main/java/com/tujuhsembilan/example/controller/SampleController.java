package com.tujuhsembilan.example.controller;

import java.text.ParseException;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.tujuhsembilan.example.repository.SessionRepository;

import io.micrometer.common.lang.NonNull;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/sample")
@RequiredArgsConstructor
public class SampleController {

  @GetMapping("/encrypted-content")
  public ResponseEntity<?> getEncryptedContent(@NonNull @CookieValue("tokenId") String tokenId,
      @NonNull @RequestHeader("x-jwejwk") String JWEjwks) throws JOSEException, ParseException {
    // decrypt JWEjwks with ecJwk which contains jwks sent by client

    ECDHDecrypter decrypter = new ECDHDecrypter(SessionRepository.getSession(tokenId));
    EncryptedJWT encJwe = EncryptedJWT.parse(JWEjwks);
    encJwe.decrypt((JWEDecrypter) decrypter);

    // convert the payload into JWT encoder
    ECKey ecKey = ECKey.parse(encJwe.getPayload().toString());

    // make the claimsSet
    JwtClaimsSet claimsSet = JwtClaimsSet.builder().claims((data) -> data.put("key", "value")).build();

    // encrypt the claimsSet with ecKey
    JWEObject jweObject = new JWEObject(
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM).build(),
        new com.nimbusds.jose.Payload(claimsSet.getClaims()));

    ECDHEncrypter encrypter = new ECDHEncrypter(ecKey);
    jweObject.encrypt(encrypter);

    return ResponseEntity.ok(jweObject.serialize());
  }
}
