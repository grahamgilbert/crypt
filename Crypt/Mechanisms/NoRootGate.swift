//
//  NoRootGate.swift
//  Crypt
//
//  Created by Joel Rennich on 11/29/17.
//  Copyright © 2017 Graham Gilbert. All rights reserved.
//

import Foundation
import os.log

class NoRootGate: CryptMechanism {
  
  @objc func run() {
  
    if self.username == "root" || self.password == "" {
      denyLogin()
    } else {
      allowLogin()
    }
  }
}
