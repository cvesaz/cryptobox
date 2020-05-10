//
//  main.cpp
//  cryptobox
//
//  Created by Christian Vessaz on 07.05.20.
//  Copyright © 2020 Christian Vessaz. All rights reserved.
//

#include <iostream>
#include "cryptobox.hpp"

int main()
{
  // Parameter
  auto keyHandle = KeyHandle("privateKey1");
  auto hash = Hash("4ebe7bf36ca8eca10ca28b2632e1a92da8e2a6f5937d6ceb86474e59159f8901");
  
  // CryptoBox test
  CryptoBox cryptoBox;
  cryptoBox.createKey(keyHandle);
  cryptoBox.signHash(hash, keyHandle);
  auto success = cryptoBox.verifySignature(hash, keyHandle);
  std::cout << "Signature verification: " << (success ? "Passed" : "Failed") << std::endl;
  
  return 0;
}
