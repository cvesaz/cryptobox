# cryptobox
Cryptographic signing box using openSSL to create an elliptic curve key, sign a hash using ECDSA and verify it.

This program uses openSSL to handle the cryptograhic tasks.

This program uses a secp256k1 elliptic curve.

This program handles at 6 actions from its command line interface:
- q : quit
- c : Create a new cryptographic secret keys and return its handle. 
- l : List all available key handle in storage map
- d : Delete a key handle from storage map
- s : Sign any 32-byte hash given a key handle
- v : Verify any signature given the signed hash and a key handle.

This program handles permanent storage of keys using a plain text file named storage.txt.

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
  https://www.openssl.org/docs/man1.0.2/man3/EC_KEY_generate_key.html
  [10.05.2020]
