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

package demo.pkcs.pkcs11.provider.keyfactory;

// class and interface imports
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.keyfactories.PKCS11KeySpec;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.utils.CryptoUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;

/**
 * This class shows a short demonstration of how to use this provider's implementation for a secret
 * key factory.
 */
public class SecretKeyFactoryDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The new PKCS#11 secret key.
   */
  protected SecretKey secretKey_;

  /**
   * The new key spec of the secret key.
   */
  protected SecretKeySpec secretKeySpec_;

  /**
   * The new PKCS#11 secret key.
   */
  protected SecretKey pkcs11SecretKey_;

  /**
   * The key spec of the secert key gained back from the PKCS#11 key.
   */
  protected SecretKeySpec pkcs11SecretKeySpec_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public SecretKeyFactoryDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    SecretKeyFactoryDemo demo = new SecretKeyFactoryDemo();

    String algorithm = "AES";
    int keyLength = 128;
    if (args.length > 1) {
      algorithm = args[0];
      keyLength = Integer.parseInt(args[1]);
    }

    demo.generateKey(algorithm, keyLength);
    demo.printSoftwareKey();
    demo.translateKeyToSpec(algorithm);
    demo.translateSpecToPkcs11Key(algorithm);
    demo.printPkcs11Key();
    demo.translatePkcs11KeyToSpec(algorithm);
    demo.printRecoveredSpec();
    demo.translateSpecsToKeyPair(algorithm);

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a key in software. It stores the key in the member variable
   * <code>secretKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateKey(String algorithm, int keyLength)
      throws GeneralSecurityException {
    System.out.print("Generating a key in software...");

    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, "IAIK");

    keyGenerator.init(keyLength);

    secretKey_ = keyGenerator.generateKey();

    System.out.println(" finished");
  }

  /**
   * Translate the software key into key specs using a factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translateKeyToSpec(String algorithm) throws GeneralSecurityException {
    System.out.print("Translating the key into key specs...");

    SecretKeyFactory softwareKeyFactory = SecretKeyFactory.getInstance(algorithm, "IAIK");

    secretKeySpec_ = (SecretKeySpec) softwareKeyFactory.getKeySpec(secretKey_,
        SecretKeySpec.class);

    System.out.println(" finished");
  }

  /**
   * Translate the software key into a PKCS#11 key using a key factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translateSpecToPkcs11Key(String algorithm) throws GeneralSecurityException {
    SecretKeyFactory pkcs11KeyFactory = SecretKeyFactory.getInstance(algorithm,
        pkcs11Provider_.getName());

    System.out.print("Translating secret key...");

    // set some PKCS#11 specific key attributes
    iaik.pkcs.pkcs11.objects.SecretKey pkcs11KeyTemplate = new iaik.pkcs.pkcs11.objects.SecretKey();
    pkcs11KeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    pkcs11KeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    pkcs11KeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
    pkcs11KeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
    // set key extractable to get key specs later
    // this is only for demo purposes - actually a private or secret key should never leave the
    // token!
    pkcs11KeyTemplate.getSensitive().setBooleanValue(Boolean.FALSE);
    pkcs11KeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
    pkcs11KeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);

    PKCS11KeySpec pkcs11KeySpec = (PKCS11KeySpec) new PKCS11KeySpec(secretKeySpec_,
        pkcs11KeyTemplate).setUseUserRole(false);

    pkcs11SecretKey_ = pkcs11KeyFactory.generateSecret(pkcs11KeySpec);

    System.out.println(" finished");
  }

  /**
   * Translate back the PKCS#11 key into a key spes using a key factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translatePkcs11KeyToSpec(String algorithm) throws GeneralSecurityException {
    SecretKeyFactory pkcs11KeyFactory = SecretKeyFactory.getInstance(algorithm,
        pkcs11Provider_.getName());

    System.out.print("Translating key into spec...");

    pkcs11SecretKeySpec_ = (SecretKeySpec) pkcs11KeyFactory.getKeySpec(pkcs11SecretKey_,
        SecretKeySpec.class);

    System.out.println(" finished");
  }

  /**
   * Translate the key specs into software keys using a factory.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void translateSpecsToKeyPair(String algorithm) throws GeneralSecurityException {
    System.out.print("Translating the encoded key specs to software keys...");

    SecretKeyFactory softwareKeyFactory = SecretKeyFactory.getInstance(algorithm, "IAIK");

    SecretKey secretKey = softwareKeyFactory.generateSecret(pkcs11SecretKeySpec_);

    if (CryptoUtils.equalsBlock(secretKey.getEncoded(), secretKey_.getEncoded())) {
      System.out.println(" finished");
    } else {
      System.out.println(" ERROR");
      throw new IAIKPkcs11Exception("keyfactory error - software keys do not match.");
    }
  }

  /**
   * This method prints the generated software key(<code>secretKey_</code>).
   */
  public void printSoftwareKey() {
    System.out
        .println("################################################################################");
    System.out.println("The generated software key is:");
    if (secretKey_ == null) {
      System.out.println("null");
    } else {
      System.out.println(secretKey_.toString());
    }
    System.out
        .println("################################################################################");
  }

  /**
   * This method prints the generated pkcs#11 key (<code>pkcs11SecretKey_</code> ).
   */
  public void printPkcs11Key() {
    System.out
        .println("################################################################################");
    System.out.println("The generated PKCS#11 key is:");
    System.out.println((pkcs11SecretKey_ != null) ? pkcs11SecretKey_.toString() : "null");
    System.out
        .println("################################################################################");
  }

  /**
   * This method prints the key spec gained from the pkcs#11 key.
   */
  public void printRecoveredSpec() {
    System.out
        .println("################################################################################");
    System.out.println("The recovered secret key spec is:");
    if (pkcs11SecretKeySpec_ != null) {
      System.out.println("Algorithm: ");
      System.out.println(pkcs11SecretKeySpec_.getAlgorithm());
      System.out.print("Value: ");
      System.out.println(Functions.toHexString(pkcs11SecretKeySpec_.getEncoded()));
    } else {
      System.out.println("null");
    }
    System.out
        .println("################################################################################");
  }

}
