# cryptobox
Cryptographic signing box using openSSL to create an elliptic curve key, sign a hash using ECDSA and verify it.

The program handle at 3 operations:
1. Create any number of new cryptographic secret keys and return their identifier/handle. 
2. Sign any 32-byte hash given a key identifier/handle.
3. Verify any signature given the signed hash and a key identifier/handle.

The program use openSSL to handle the cryptograhic tasks.
The chosen elliptic curve is secp256k1.

References:
- Elliptic curve digital signature algorithm
  https://fr.wikipedia.org/wiki/Elliptic_curve_digital_signature_algorithm
  [08.05.2020]
- Signing a message using ECDSA in OpenSSL 
  https://stackoverflow.com/questions/2228860/signing-a-message-using-ecdsa-in-openssl
  [09.05.2020]
- OpenSSL ECDSA
  https://www.openssl.org/docs/man1.0.2/man3/ECDSA_sign.html
  [09.05.2020]
