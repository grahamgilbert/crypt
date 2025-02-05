/*
 Crypt
 
 Copyright 2025 The Crypt Project.
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */
import os.log

let keychainLog = OSLog(subsystem: cryptBundleID, category: "Keychain")
let filevaultLog = OSLog(subsystem: cryptBundleID, category: "Filevault")
let prefLog = OSLog(subsystem: cryptBundleID, category: "Preferences")
let enablementLog = OSLog(subsystem: cryptBundleID, category: "Enablement")
let coreLog = OSLog(subsystem: cryptBundleID, category: "Core")
let checkLog = OSLog(subsystem: cryptBundleID, category: "Check")
