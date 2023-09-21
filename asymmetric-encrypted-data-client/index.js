// run with "bun index.js"

import JOSE from "node-jose";
import { fetch, CookieJar } from "node-fetch-cookies";

const cookieJar = new CookieJar();

const createClientJWKS = async () => {
  const key = await JOSE.JWK.createKeyStore().generate("EC", "P-256");
  return key;
};

// get jwks from server
const getJWKSFromServer = () =>
  // generate single use JWK public key
  createClientJWKS().then((clientJWKS) =>
    fetch(cookieJar, "http://localhost:8091/auth/jwk", {
      headers: {
        Authorization: `Basic U1lTVEVNOlNZU0FETQ==`,
      },
      method: "POST",
      body: JSON.stringify(clientJWKS.toJSON()),
    }).then((res) => res.text())
      .then((JWK) =>
        JOSE.JWE.createDecrypt(clientJWKS).decrypt(JWK)
      ).then((result) =>
        JOSE.JWK.asKey(
          JSON.parse(result.plaintext.toString()).key)
      )
  )

const requestDataFromServer = async (
  clientJWKS,
  encryptedClientJWKSPublicKey
) => {
  return fetch(cookieJar, "http://localhost:8091/sample/encrypted-content", {
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
