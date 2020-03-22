#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import unittest
import server

class ServerTestCase(unittest.TestCase):
    def test_0_getMechanismInfo(self):
        server.Example_getMechanismInfo()

    def test_1_encryptAndDecrypt(self):
        server.Example_encryptAndDecrypt()

    def test_2_digest(self):
        server.Example_digest()
        
    def test_3_signAndVerifyUsingRSAKeyPair(self):
        server.Example_signAndVerifyUsingRSAKeyPair()
        
    def test_4_signAndVerifyUsingECDSAKeyPair(self):
        server.Example_signAndVerifyUsingECDSAKeyPair()
        
    @unittest.expectedFailure
    def test_5_signAndVerifyToTestErrorHandling(self):
        server.Example_signAndVerifyToTestErrorHandling()
        
    def test_6_wrapAndUnwrapKey(self):
        server.Example_wrapAndUnwrapKey()
        
    def test_7_deriveKey(self):
        server.Example_deriveKey()
