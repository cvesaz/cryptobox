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
  
  // Load stored keys
  loadKeys();
}

// Destructor
// REMARK the memory of private keys generated in createKey() and signatures generated in signHash() have to be free
CryptoBox::~CryptoBox() {
  // Store private keys to storage file
  storeKeys();
  
  // Free memory from private keys
  for (const auto& it: handles2eckeys) {
    EC_KEY_free(it.second);
  }
  
  // Free memory from signatures
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
  bool success(true);
  EC_KEY* eckey = EC_KEY_new();
  if (!eckey) {
    std::cout << "Failed to create new EC Key..." << std::endl;
    success = false;
  }
  EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(EC_CURVE);
  if (!ecgroup) {
    std::cout << "Failed to create new EC Group..." << std::endl;
    success = false;
  }
  if (EC_KEY_set_group(eckey, ecgroup)==0) {
    std::cout << "Failed to set group for EC Key..." << std::endl;
    success = false;
  }
  if (EC_KEY_generate_key(eckey)==0) {
    std::cout << "Failed to generate EC Key..." << std::endl;
    success = false;
  }
  EC_GROUP_free(ecgroup);
  if (!success) {
    EC_KEY_free(eckey);
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
  ECDSA_SIG* signature = ECDSA_do_sign((const unsigned char*)hash.c_str(), (int)hash.size(), eckey);
  if (!signature) {
    std::cout << "Failed to generate EC Signature..." << std::endl;
    ECDSA_SIG_free(signature);
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

// List available keyHandles in storage map
void CryptoBox::listKeyHandles() const {
  for (const auto& it: handles2eckeys) {
    std::cout << (it.first) << std::endl;
  }
}

// Delete a private key from storage map using keyHandle
void CryptoBox::deleteKeyHandle(const KeyHandle& keyHandle) {
  auto it = handles2eckeys.find(keyHandle);
  if (it==handles2eckeys.end()) {
    std::cout << "Failed to get key from " << keyHandle << "..." << std::endl;
    return nullptr;
  }
  EC_KEY_free(handles2eckeys.at(keyHandle));
  handles2eckeys.erase(it);
  std::cout << "Deleted " << keyHandle << " from storage..." << std::endl;
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

// Store map of keyHandle to private key into file
void CryptoBox::storeKeys() {
  // Check if storage is required
  if (handles2eckeys.size()==0) {
    std::cout << "No keys to store in file..." << std::endl;
    return;
  }
  
  // Build stream of key data
  std::stringstream ss;
  for (const auto& it: handles2eckeys) {
    bool success(true);
    ss << it.first << " ";
    EC_GROUP *ecgroup = EC_GROUP_new_by_curve_name(EC_CURVE);
    if (!ecgroup) {
      std::cout << "Failed to create new EC Group..." << std::endl;
      success = false;
    }
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (EC_POINT_get_affine_coordinates(ecgroup, EC_KEY_get0_public_key(it.second), x, y, NULL)==0) {
      std::cout << "Failed to get ecpoint..." << std::endl;
      success = false;
    }
    std::string x_str = BN_bn2hex(x);
    ss << x_str << " ";
    std::string y_str = BN_bn2hex(y);
    ss << y_str << " ";
    std::string p_str = BN_bn2hex(EC_KEY_get0_private_key(it.second));
    ss << p_str << std::endl;
    BN_free(y);
    BN_free(x);
    EC_GROUP_free(ecgroup);
    if (!success) return;
  }
  
  // Store map
  std::ofstream outfile;
  outfile.open(STORAGE_FILE);
  outfile << ss.str();
  outfile.close();
  std::cout << "Private keys stored in file..." << std::endl;
}

// Load map of keyHandle to private key from file
void CryptoBox::loadKeys() {
  // Load storage file
  std::stringstream ss;
  std::ifstream infile;
  infile.open(STORAGE_FILE);
  if (!infile) {
    std::cout << "No keys to load from file..." << std::endl;
    return;
  }
  ss << infile.rdbuf();
  infile.close();

  // Create EC key from key data
  KeyHandle keyHandle;
  while (ss >> keyHandle) {
    bool success(true);
    std::string x_str, y_str, p_str;
    ss >> x_str >> y_str >> p_str;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *p = BN_new();
    BN_hex2bn(&x, x_str.c_str());
    BN_hex2bn(&y, y_str.c_str());
    BN_hex2bn(&p, p_str.c_str());
    EC_KEY* eckey = EC_KEY_new();
    EC_GROUP* ecgroup = EC_GROUP_new_by_curve_name(EC_CURVE);
    if (!ecgroup) {
      std::cout << "Failed to create new EC Group..." << std::endl;
      success = false;
    }
    if (EC_KEY_set_group(eckey, ecgroup)==0) {
      std::cout << "Failed to set group for EC Key..." << std::endl;
      success = false;
    }
    EC_POINT* ecpoint = EC_POINT_new(ecgroup);
    if (EC_POINT_set_affine_coordinates(ecgroup, ecpoint, x, y, NULL)==0) {
      std::cout << "Failed to set ecpoint..." << std::endl;
      success = false;
    }
    if (EC_KEY_set_public_key(eckey, ecpoint)==0) {
      std::cout << "Failed to set public key..." << std::endl;
      success = false;
    }
    if (EC_KEY_set_private_key(eckey, p)==0) {
      std::cout << "Failed to set private key..." << std::endl;
      success = false;
    }
    EC_POINT_free(ecpoint);
    EC_GROUP_free(ecgroup);
    BN_free(p);
    BN_free(y);
    BN_free(x);
    if (!success) return;
    handles2eckeys[keyHandle] = eckey;
  }
  
  // Delete the storage file
  remove(STORAGE_FILE);
  std::cout << "Private keys loaded from file: " << std::endl;
  listKeyHandles();
}
