//
//  cryptobox.cpp
//  cryptobox
//
//  Created by Christian Vessaz on 09.05.20.
//  Copyright © 2020 Christian Vessaz. All rights reserved.
//

#include "cryptobox.hpp"

// Constructor
CryptoBox::CryptoBox() {
  std::cout << "Built a CryptoBox..." << std::endl;
}

// Destructor
// REMARK the memory of private keys generated in createKey() and signatures generated in signHash() have to be free
CryptoBox::~CryptoBox() {
  for (const auto& it: handles2eckeys) {
    EC_KEY_free(it.second);
  }
  for (const auto& it : signaturesWallet) {
    ECDSA_SIG_free(it.second);
  }
  std::cout << "Deleted a CryptoBox..." << std::endl;
}

// Create a private key and assign a given keyHandle
// keyHandle: a user given keyHandle
// REMARK the memory of private key is allocated in this function
void CryptoBox::createKey(const KeyHandle& keyHandle) {
  // Check if keyHandle is available in the handles2eckeys map for a new EC Key generation
  auto it = handles2eckeys.find(keyHandle);
  if (it!=handles2eckeys.end()) {
    std::cout << "Failed to create key, " << keyHandle << " already exists..." << std::endl;
    return;
  }
  
  // Check if the keyHandle is valid
  if (keyHandle.size()==0) {
    std::cout << "Failed to create key, keyHandle is empty..." << std::endl;
    return;
  }
  
  // Generate a new EC Key
  EC_KEY* eckey = EC_KEY_new();
  if (!eckey) {
    std::cout << "Failed to create new EC Key..." << std::endl;
    return;
  }
  EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(EC_CURVE);
  if (!ecgroup) {
    std::cout << "Failed to create new EC Group..." << std::endl;
    return;
  }
  if (EC_KEY_set_group(eckey, ecgroup)==0) {
    std::cout << "Failed to set group for EC Key..." << std::endl;
    return;
  }
  if (EC_KEY_generate_key(eckey)==0) {
    std::cout << "Failed to generate EC Key..." << std::endl;
    return;
  }
  
  // Insert the generated EC Key to the handles2eckeys map
  std::cout << "New EC Key generated using " << keyHandle << " handle..." << std::endl;
  handles2eckeys[keyHandle] = eckey;
}

// Create a signature of a given hash using a given keyHandle
// hash: a user given hash
// keyHandle: a user given keyHandle
// REMARK the memory of the signature is allocated in this function
void CryptoBox::signHash(const Hash& hash, const KeyHandle& keyHandle) {
  // Get EC Key from keyHandle
  auto eckey = getKey(keyHandle);
  if (!eckey) return;
  
  // Sigh hash using EC Key from keyHandle
  auto signature = ECDSA_do_sign((const unsigned char*)hash.c_str(), (int)hash.size(), eckey);
  if (!signature) {
    std::cout << "Failed to generate EC Signature..." << std::endl;
    return;
  }
  
  // Insert the signature into the signaturesWallet
  std::cout << "New signature inserted in signaturesWallet..." << std::endl;
  signaturesWallet[std::make_pair(hash, keyHandle)] = signature;
}

// Verify a signature of a given hash using a given keyHandle
// hash: a user given hash
// keyHandle: a user given keyHandle
bool CryptoBox::verifySignature(const Hash& hash, const KeyHandle& keyHandle) const {
  // Get EC Key from keyHandle
  auto eckey = getKey(keyHandle);
  if (!eckey) return false;
  
  // Get ECDSA_SIG from signaturesWallet
  auto it = signaturesWallet.find(std::make_pair(hash, keyHandle));
  if (it==signaturesWallet.end()) {
    std::cout << "Failed to get the signature from signaturesWallet..." << std::endl;
    return false;
  }
  auto signature = it->second;
  
  // Verify signature
  if (ECDSA_do_verify((const unsigned char*)hash.c_str(), (int)hash.size(), signature, eckey) != 1) {
    std::cout << "Failed to verify EC Signature..." << std::endl;
    return false;
  }
  std::cout << "Verifed EC Signature..." << std::endl;
  return true;
}

// Get a private key from a given keyHandle
// keyHandle: a user given keyHandle
// return: a pointer to private key
EC_KEY* CryptoBox::getKey(const KeyHandle& keyHandle) const {
  auto it = handles2eckeys.find(keyHandle);
  if (it==handles2eckeys.end()) {
    std::cout << "Failed to get key from " << keyHandle << "..." << std::endl;
    return nullptr;
  }
  return handles2eckeys.at(keyHandle);
}
