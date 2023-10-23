package com.tujuhsembilan.example.controller;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.tujuhsembilan.example.configuration.property.AuthProp;
import com.tujuhsembilan.example.repository.SessionRepository;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;

@Validated
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class BasicLoginController {

  private final ObjectMapper objMap;

  private final JwtEncoder jwtEncoder;
  private final AuthProp authProp;

  @PostMapping("/jwk")
  public ResponseEntity<?> jwk(@NonNull @RequestBody String clientJWKS, HttpServletResponse response)
      throws JsonProcessingException, JOSEException, ParseException {
    // parse client jwks to public key
    ECKey ecKey = ECKey.parse(clientJWKS);

    // create encrypter
    var encrypter = new ECDHEncrypter(ecKey);

    // make the session JWK
    String tokenId = SessionRepository.createSession();

    JwtClaimsSet claimsSet = JwtClaimsSet.builder()
        .claim("key", SessionRepository.getSession(tokenId).toPublicJWK().toJSONString()).build();

    // encrypt the claimsSet with ecKey
    var jweObject = new JWEObject(
        new JWEHeader.Builder(com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A256KW, com.nimbusds.jose.EncryptionMethod.A256GCM)
            .build(),
        new Payload(claimsSet.getClaims()));

    jweObject.encrypt(encrypter);

    // set cookie tokenId with value tokenId
    Cookie cookie = new Cookie("tokenId", tokenId);
    cookie.setHttpOnly(true);

    response.addCookie(cookie);

    return ResponseEntity.ok(jweObject.serialize());
  }

  // You MUST login using BASIC AUTH, NOT POST BODY
  @PostMapping("/login")
  public ResponseEntity<?> login(@NotNull Authentication auth) {
    var jwt = jwtEncoder
        .encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.ES512).build(),
            JwtClaimsSet.builder()
                .issuer(authProp.getUuid())
                .audience(List.of(authProp.getUuid()))
                .subject(((User) auth.getPrincipal()).getUsername())
                // You SHOULD set expiration, claims, etc here too
                .build()));
    return ResponseEntity.ok(jwt.getTokenValue());
  }

}
