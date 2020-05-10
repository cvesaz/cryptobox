//
//  main.cpp
//  cryptobox
//
//  Created by Christian Vessaz on 07.05.20.
//  Copyright © 2020 Christian Vessaz. All rights reserved.
//

// std
#include <iostream>
#include <sstream>

// cryptobox
#include "cryptobox.hpp"

// macros
#define CIN_HASH            char hash[64]; \
cout << "Enter a hash : "; \
cin >> hash; \
fflush(stdin);
#define CIN_KEYHANDLE       char keyHandle[32]; \
cout << "Enter a keyHandle : "; \
cin >> keyHandle; \
fflush(stdin);
#define CIN_HASH_KEYHANDLE  CIN_HASH \
CIN_KEYHANDLE

using namespace std;

int main()
{
  // Usage info
  stringstream usageInfo;
  usageInfo << "Available actions are:" << endl;
  usageInfo << "   q : quit" << endl;
  usageInfo << "   c : createKey" << endl;
  usageInfo << "   l : listKeyHandles" << endl;
  usageInfo << "   d : deleteKeyHandles" << endl;
  usageInfo << "   s : signHash" << endl;
  usageInfo << "   v : verifySignature" << endl;
  
  // CryptoBox test
  CryptoBox cryptoBox;
  
  // Start command line interface
  // TODO create an interface using Qt
  cout << usageInfo.str();
  while (true) {
    // Get action
    char action;
    cout << "Choose an action : ";
    cin >> action;
    fflush(stdin);
    
    // Exit
    if (action=='q') {
      break;
    }
    
    // Create Key
    else if (action=='c') {
      CIN_KEYHANDLE
      cryptoBox.createKey(keyHandle);
    }
    
    // List KeyHandles
    else if (action=='l') {
      cryptoBox.listKeyHandles();
    }
    
    // Delete KeyHandle
    else if (action=='d') {
      CIN_KEYHANDLE
      cryptoBox.deleteKeyHandle(keyHandle);
    }
    
    // Sign Hash
    else if (action=='s') {
      CIN_HASH_KEYHANDLE
      cryptoBox.signHash(hash, keyHandle);
    }
    
    // Verify Signature
    else if (action=='v') {
      CIN_HASH_KEYHANDLE
      auto success = cryptoBox.verifySignature(hash, keyHandle);
      cout << "Signature verification: " << (success ? "Passed" : "Failed") << endl;
    }
    
    // Usage Info
    else {
      cout << usageInfo.str();
    }
  }
  
  return 0;
}
