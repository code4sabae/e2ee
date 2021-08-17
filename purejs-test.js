import { ECDH, ZeroableUint8Array } from "https://taisukef.github.io/ECDH-es/ECDH.js";
//import { ECDH, ZeroableUint8Array } from "../../util/ECDH-es/ECDH.js";
import { hex } from "https://code4sabae.github.io/js/hex.js";
import { AESGCM } from "https://taisukef.github.io/AES-GCM-es/AESGCM.js";

//enable debugging
ECDH.zeroSetDebug(true);

const type = "secp256r1";
const curve = ECDH.getCurve(type);
let iv = null;

const keypair = ECDH.generateKeys(curve);
const ecdhpublickey_value = keypair.publicKey.buffer.toHexString();
const ecdhprivatekey_value = keypair.privateKey.buffer.toHexString();

const ecdhpublickey2_value = ecdhpublickey_value; // test!

const privateKey = ECDH.PrivateKey.fromBuffer(curve, ZeroableUint8Array.fromHexString(ecdhprivatekey_value, ecdhprivatekey_value.length / 2));
const peerPublicKey = ECDH.PublicKey.fromBuffer(curve, ZeroableUint8Array.fromHexString(ecdhpublickey2_value, ecdhpublickey2_value.length / 2));

const secretKey = privateKey.deriveSharedSecret(peerPublicKey);
const ecdhsecretkey_value = hex.fromBin(secretKey);
iv = AESGCM.createIV();

const ecdhmessage_value = "テスト";

const data = new TextEncoder().encode(ecdhmessage_value);
const key = hex.toBin(ecdhsecretkey_value);
AESGCM.incrementIV(iv);
const [encdata, tag] = AESGCM.encrypt(key, iv, data);
const ecdhciphertext_value = hex.fromBin(iv) + "_" + hex.fromBin(encdata) + "_" + hex.fromBin(tag);

//const key = hex.toBin(ecdhsecretkey_value);
const [iv2, encdata2, tag2] = ecdhciphertext_value.split("_").map(h => hex.toBin(h));
const data2 = AESGCM.decrypt(key, iv2, encdata2, tag2);
const ecdhmessage_value2 = data2 ? new TextDecoder().decode(data2) : "復号失敗";

console.log(ecdhmessage_value2);

keypair.privateKey.zero();
keypair.publicKey.zero();
privateKey.zero();
peerPublicKey.zero();
secretKey.zero();

//debug ECDH -- should not throw!
ECDH.zeroDebug();
