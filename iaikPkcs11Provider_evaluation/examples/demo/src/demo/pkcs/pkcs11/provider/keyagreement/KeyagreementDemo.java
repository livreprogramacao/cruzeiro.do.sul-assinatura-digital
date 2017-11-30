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

package demo.pkcs.pkcs11.provider.keyagreement;

// class and interface imports
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.provider.ComparableByteArray;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.keyagreements.PKCS11KeyAgreementSpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;

/**
 * This class shows a short demonstration of how to use this provider's implementation for
 * Elliptic-Curve Diffie-Hellman key agreement.
 * 
 * @author Florian Reimair
 */
public class KeyagreementDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * This constructor registers the new provider to the Java security system.
   */
  public KeyagreementDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    KeyagreementDemo demo = new KeyagreementDemo();

    String algorithm = (args.length > 0) ? args[0] : "ECDH";

    // generate key pair for user a
    KeyPair keya = demo.generateKeyPair(algorithm);
    demo.printSoftwareKeyPair("The first generated software key-pair is:", keya);
    // generate key pair for user b
    KeyPair keyb = demo.generateKeyPair(algorithm);
    demo.printSoftwareKeyPair("The second generated software key-pair is:", keyb);
    // each user performs the key agreement
    SecretKey sharedSecretA = demo.doAgreement(algorithm, keya.getPrivate(),
        keyb.getPublic());
    SecretKey sharedSecretB = demo.doAgreement(algorithm, keyb.getPrivate(),
        keya.getPublic());

    // the secrets must be equal otherwise there was an error
    if (demo.testSecretKeys(sharedSecretA, sharedSecretB)) {
      System.out.println("Now user1 and user2 share a common secret!");
    } else {
      System.out.println(algorithm + " key agreement ERROR!");
      throw new IAIKPkcs11Exception(algorithm + " key agreement error: secrets mismatch");
    }

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a key-pair using the IAIK PKCS#11 provider.
   * 
   * @return the fresh key pair
   * @throws GeneralSecurityException
   *           If anything with the provider fails.
   */
  public KeyPair generateKeyPair(String algorithm) throws GeneralSecurityException,
      IOException {
    System.out.print("Generating a key-pair...");

    String keyAlgorithm = algorithm;
    if (algorithm.equalsIgnoreCase("ecdh")) {
      keyAlgorithm = "ecdsa";
    }
    KeyPair keyPair = KeyFinder.generateDerivationKeyPair(pkcs11Provider_, keyAlgorithm);

    System.out.println("finished");
    return keyPair;
  }

  /**
   * This method performs the key agreement process.
   * 
   * @param user1PrK
   *          private key of one user
   * @param user2PuK
   *          public key of the other user
   * @return the resulting shared key
   * @throws GeneralSecurityException
   *           the general security exception
   */
  public SecretKey doAgreement(String algorithm, PrivateKey user1PrK, PublicKey user2PuK)
      throws GeneralSecurityException {

    System.out.print("Perform the key agreement process...");

    // get the KeyAgreement tool
    KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm,
        pkcs11Provider_.getName());

    // supply the local pear's private key to init the process
    DES3SecretKey template = new DES3SecretKey();
    template.getEncrypt().setBooleanValue(Boolean.TRUE);
    template.getDecrypt().setBooleanValue(Boolean.TRUE);
    template.getToken().setBooleanValue(Boolean.FALSE); // make it a session object
    template.getPrivate().setBooleanValue(Boolean.TRUE); // make it private
    PKCS11KeyAgreementSpec spec = new PKCS11KeyAgreementSpec(template);
    keyAgreement.init(user1PrK, spec);

    // supply the remote public key to complete a phase and get a phase key
    keyAgreement.doPhase(user2PuK, true);

    SecretKey secretKey = keyAgreement.generateSecret("DESede");

    System.out.println("finished");

    return secretKey;
  }

  public boolean testSecretKeys(SecretKey secretKeya, SecretKey secretKeyb)
      throws GeneralSecurityException {
    byte[] testdata = "This is some data to be encrypted.".getBytes();

    Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding",
        pkcs11Provider_.getName());
    cipher.init(Cipher.ENCRYPT_MODE, secretKeya);
    byte[] cipherText = cipher.doFinal(testdata);

    cipher.init(Cipher.DECRYPT_MODE, secretKeyb, cipher.getParameters());
    byte[] plainText = cipher.doFinal(cipherText);

    ComparableByteArray originalData = new ComparableByteArray(testdata);
    ComparableByteArray recoveredData = new ComparableByteArray(plainText);

    if (recoveredData.equals(originalData)) {
      return true;
    } else {
      return false;
    }
  }

  /**
   * This method prints a software key-pair.
   */
  public void printSoftwareKeyPair(String title, KeyPair keyPair) {
    System.out
        .println("################################################################################");
    System.out.println(title);
    if (keyPair == null) {
      System.out.println("null");
    } else {
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Public key:");
      System.out.println(keyPair.getPublic());
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Private key:");
      System.out.println(keyPair.getPrivate());
    }
    System.out
        .println("################################################################################");
  }

}
