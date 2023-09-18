// run with "bun index.js"

import JOSE from "node-jose";
import crypto from "crypto";
import fetch from "node-fetch";
import fs from "fs";

// get jwks from server
const getJWKSFromServer = () =>
  fetch("http://localhost:8091/auth/jwks.json")
    .then((res) => res.json())
    .then((jwks) => {
      return JOSE.JWK.asKey(jwks.keys[0]);
    });

const createClientJWKS = async () => {
  const key = await JOSE.JWK.createKeyStore().generate("EC", "P-256");
  return key;
};

const requestDataFromServer = async (
  clientJWKS,
  encryptedClientJWKSPublicKey
) => {
  return fetch("http://localhost:8091/sample/encrypted-content", {
    headers: {
      Authorization: `Basic U1lTVEVNOlNZU0FETQ==`,
      "Content-Type": "*/*",
      "x-jwejwk": encryptedClientJWKSPublicKey,
    },
  })
    .then((res) => res.text())
    .then((data) => {
      console.log("encrypted", data);
      return JOSE.JWE.createDecrypt(clientJWKS).decrypt(data)
    });
};

const serverJWKS = await getJWKSFromServer();
const clientJWKS = await createClientJWKS();

// compacted JWE
const encryptedClientJWKSPublicKey = await JOSE.JWE.createEncrypt(
  {
    format: "compact",
  },
  serverJWKS
)
  .update(JSON.stringify(clientJWKS.toJSON()))
  .final()
  .then((result) => {
    return result;
  });

//request data from server
requestDataFromServer(clientJWKS, encryptedClientJWKSPublicKey).then((data) => {
  //decrypt data using client private key
  console.log("decrypted", data.plaintext.toString());
});
