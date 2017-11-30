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

package demo.pkcs.pkcs11.provider.keygeneration;

// class and interface imports
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keygenerators.PKCS11KeyDerivationSpec;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11SecretKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;
import demo.pkcs.pkcs11.provider.utils.KeyTemplateDemo;

/**
 * This class demonstrates how to use this provider implementation for key derivation. If uses a
 * base key and derives a new key from this base key using a PKCS#11 mechanism.
 */
public class KeyDerivationDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The base key. In this case only a proxy object, but the application cannot see this.
   */
  protected SecretKey key_;

  /**
   * The derived key. In this case only a proxy object, but the application cannot see this.
   */
  protected SecretKey derivedKey_;

  /**
   * Here the actual signature is stored compliant to PKCS#11
   */
  protected byte[] mac_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public KeyDerivationDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    KeyDerivationDemo demo = new KeyDerivationDemo();

    String algorithm = (args.length > 0) ? args[0] : "MD5Derivation";

    demo.getOrGenerateKey();
    demo.deriveKey(algorithm);
    demo.printKeys();
    System.out.flush();
    System.err.flush();
  }

  /**
   * First, this method tries to find a generic secret key on a token. If there is none, this method
   * generates a temporary generic secret key. It stores the key in the member variable
   * <code>key_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void getOrGenerateKey() throws GeneralSecurityException, IOException {
    try {
      key_ = KeyFinder.findDerivationSecretKey(pkcs11Provider_, "AES");
    } catch (KeyException e) {
      key_ = KeyFinder.generateDerivationSecretKey(pkcs11Provider_, "AES");
    }
  }

  /**
   * This method derives a new key from the base key.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void deriveKey(String algorithm) throws GeneralSecurityException {
    // Get a KeyGenerator object for key derivation from our new provider
    KeyGenerator derivationEngine = KeyGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());

    // template for derived key
    iaik.pkcs.pkcs11.objects.SecretKey derivationTemplate = KeyTemplateDemo
        .getSignatureSecretKeyTemplate("AES");

    // create parameter spec
    iaik.pkcs.pkcs11.objects.SecretKey pkcs11BaseKeyObject = (iaik.pkcs.pkcs11.objects.SecretKey) ((IAIKPKCS11SecretKey) key_)
        .getKeyObject();
    PKCS11KeyDerivationSpec derivationSpec = (PKCS11KeyDerivationSpec) new PKCS11KeyDerivationSpec(
        pkcs11BaseKeyObject, derivationTemplate).setUseAnonymousRole(false);

    // initialize KeyGenerator
    derivationEngine.init(derivationSpec);

    // derive the key
    derivedKey_ = derivationEngine.generateKey();
  }

  /**
   * Print information about the base key and the derived key.
   */
  public void printKeys() {
    System.out.println("##########");

    System.out.println("The base key is:");
    System.out.println(key_);

    System.out.println("____________________________________________________");

    System.out.println("The derived key is:");
    System.out.println(derivedKey_);

    System.out.println("##########");
  }

}
