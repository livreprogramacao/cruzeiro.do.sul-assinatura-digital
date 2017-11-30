// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2015 Stiftung Secure Information and
//                           Communication Technologies SIC
// http://www.sic.st
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

package demo.pkcs.pkcs11.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;

/**
 * This is a simple demo that shows how to change the user PIN of a PKCS#11 token.
 */
public class ChangePINDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  public ChangePINDemo() {
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws TokenException, GeneralSecurityException,
      IOException {

    // if the user PIN and the new user PIN are known, we can provide them
    char[] oldUserPIN = (args.length > 0) ? args[0].toCharArray() : null;
    char[] newUserPIN = (args.length > 1) ? args[1].toCharArray() : null;

    ChangePINDemo demo = new ChangePINDemo();
    // change PIN with specified PINs using the TokenManager
    // if pins are null, they have to be entered via prompt
    demo.changePinWithTokenManager(oldUserPIN, newUserPIN);
    // or change PIN with specified PINs using the KeyStore
    // if pins are null, they have to be entered via prompt
    demo.changePinWithKeystore(oldUserPIN, newUserPIN);
  }

  public void changePinWithTokenManager(char[] oldPin, char[] newPin)
      throws TokenException {
    // call the token manager of this provider instance, to change the user PIN using the default
    // dialog settings for changing the user PIN, if we set the PIN, no dialog will pop up
    pkcs11Provider_.getTokenManager().setUserPIN(null, oldPin, newPin);

    System.out.println("Changed user PIN successfully.");

  }

  public void changePinWithKeystore(char[] oldPin, char[] newPin)
      throws GeneralSecurityException, IOException {
    // with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
    // specific IAIKPkcs11 provider instance after this call, even if you specify the provider
    // at this call. this is a limitation of SUN's KeyStore concept. the KeyStoreSPI object
    // has no chance to get its own provider instance.
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore",
        pkcs11Provider_.getName());

    // load the keystore of the PKCS#11 provider given via input stream
    String providerName = pkcs11Provider_.getName();
    ByteArrayInputStream providerNameInputStream = new ByteArrayInputStream(
        providerName.getBytes("UTF-8"));
    // if the user PIN is known, we can provider it, this avoids a dialog to pop up
    tokenKeyStore.load(providerNameInputStream, oldPin);

    // a call to store, causes the PKCS#11 provider to change the user PIN of the underlying token
    // if the new PIN is known, we can provider it, this avoids a dialog to pop up
    // we can provide an output stream, it will contain the same data as the input stream provided
    // to load()
    ByteArrayOutputStream keyStoreOutputStream = new ByteArrayOutputStream();
    tokenKeyStore.store(keyStoreOutputStream, newPin);

    System.out.println("Changed user PIN successfully.");
  }

}
