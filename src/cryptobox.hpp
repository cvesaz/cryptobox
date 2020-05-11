//
//  cryptobox.hpp
//  cryptobox
//
//  Created by Christian Vessaz on 09.05.20.
//  Copyright © 2020 Christian Vessaz. All rights reserved.
//

#ifndef cryptobox_hpp
#define cryptobox_hpp

// std
#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <stdio.h>

// openssl
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

// Elliptic curve
#define EC_CURVE NID_secp256k1
// Storage file
#define STORAGE_FILE "storage.txt"

// Typedef
typedef std::string KeyHandle;
typedef std::string Hash;

class CryptoBox {
private:
  // Storage map of keyHandle to private key
  std::map<KeyHandle,EC_KEY*> handles2eckeys;
  // Sorage hash and keyHandle to signature
  std::map<std::pair<Hash,KeyHandle>,ECDSA_SIG*> signaturesWallet;
  
public:
  // Constructor
  CryptoBox();
  // Destructor
  ~CryptoBox();
  // Create a private key and assign a given keyHandle
  void createKey(const KeyHandle& keyHandle);
  // Create a signature of a given hash using a given keyHandle
  void signHash(const Hash& hash, const KeyHandle& keyHandle);
  // Verify a signature of a given hash using a given keyHandle
  bool verifySignature(const Hash& hash, const KeyHandle& keyHandle) const;
  // List available keyHandles in storage map
  void listKeyHandles() const;
  // Delete a private key from storage map using keyHandle
  void deleteKeyHandle(const KeyHandle& keyHandle);
  
private:
  // Get a private key from a given keyHandle
  EC_KEY* getKey(const KeyHandle& keyHandle) const;
  // Store map of keyHandle to private key into file
  void storeKeys();
  // Load map of keyHandle to private key from file
  void loadKeys();
};

#endif /* cryptobox_hpp */
