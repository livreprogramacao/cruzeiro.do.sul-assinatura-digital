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

package demo.pkcs.pkcs11.provider.ciphers;

//class and interface imports
import iaik.pkcs.pkcs11.provider.ComparableByteArray;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;

/**
 * This class shows a short demonstration of how to use this provider implementation for asymmetric
 * encryption and decryption. Most parts are identical to applications using other providers. The
 * only difference is the treatment of keystores. Smart card keystores cannot be read from streams
 * in general.
 */
public class AsymmetricCipherDemo {

  /**
   * The data that will be encrypted. A real application would e.g. read it from file.
   */
  protected static byte[] DATA = "This is some data to be encrypted.".getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The decryption key. In this case only a proxy object, but the application cannot see the
   * difference.
   */
  protected PrivateKey decryptionKey_;

  /**
   * This is the key used for encryption.
   */
  protected PublicKey encryptionKey_;

  /**
   * This is the encrypted data.
   */
  protected byte[] cipherText_;

  /**
   * The initialization vector for the cipher in CBC mode.
   */
  protected byte[] initializationVector_ = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

  /**
   * The decrpytion cipher engine.
   */
  protected Cipher decryptionEngine_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public AsymmetricCipherDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    AsymmetricCipherDemo demo = new AsymmetricCipherDemo();

    String algorithm = (args.length > 0) ? args[0] : "RSA";
    String padding = "pkcs1padding";

    demo.getOrGenerateKey(algorithm);
    demo.encryptData(algorithm, padding);
    demo.decryptData(algorithm, padding);
    demo.decryptDataAgain();
    System.out.flush();
    System.err.flush();
  }

  /**
   * First, this method tries to find the required keys on a token. If there are none, this method
   * generates a temporary key pair and stores them in the member variables
   * <code>encryptionKey_</code> and <code>decryptionKey_</code>.
   * 
   * @throws GeneralSecurityException
   *           If anything with the provider fails.
   * @throws IOException
   *           If initializing the key store fails.
   */
  public void getOrGenerateKey(String algorithm) throws GeneralSecurityException,
      IOException {
    KeyPair keyPair;
    try {
      keyPair = KeyFinder.findCipherKeyPair(pkcs11Provider_, algorithm);
    } catch (KeyException e) {
      keyPair = KeyFinder.generateCipherKeyPair(pkcs11Provider_, algorithm);
    }
    encryptionKey_ = keyPair.getPublic();
    decryptionKey_ = keyPair.getPrivate();
  }

  /**
   * This method encrypts the data. It uses the software provider for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If encryption fails for some reason.
   */
  public void encryptData(String algorithm, String padding)
      throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("Encrypting this data: \"");
    System.out.print(new String(DATA));
    System.out.println("\"");
    System.out.println();

    System.out.print("encrypting... ");

    // get a cipher object from the PKCS#11 provider for encryption
    Cipher encryptionEngine = Cipher.getInstance(algorithm + "/ECB/" + padding,
        pkcs11Provider_.getName());

    // initialize for encryption with the secret key
    encryptionEngine.init(Cipher.ENCRYPT_MODE, encryptionKey_);

    // put the original data and encrypt it
    cipherText_ = encryptionEngine.doFinal(DATA);

    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * This method decrypts the data. It uses the PKCS#11 provider for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If decryption fails for some reason.
   */
  public void decryptData(String algorithm, String padding)
      throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("decrypting... ");

    // Get a cipher object from our new provider
    decryptionEngine_ = Cipher.getInstance(algorithm + "/ECB/" + padding,
        pkcs11Provider_.getName());

    // initialize for decryption with our secret key
    decryptionEngine_.init(Cipher.DECRYPT_MODE, decryptionKey_);

    // decrpyt the data
    byte[] recoveredPlainText = decryptionEngine_.doFinal(cipherText_);

    System.out.println("finished");

    // put the data that should be signed
    System.out.println("The recovered data is:");
    System.out.print("\"");
    System.out.print(new String(recoveredPlainText));
    System.out.println("\"");
    System.out.println();

    ComparableByteArray originalData = new ComparableByteArray(DATA);
    ComparableByteArray recoveredData = new ComparableByteArray(recoveredPlainText);

    if (recoveredData.equals(originalData)) {
      System.out.println("decrypted and original data match - SUCCESS");
    } else {
      System.out.println("decrypted and original data mismatch - FAILURE");
      throw new IAIKPkcs11Exception(
          "Decryption error: decrypted and original data mismatch");
    }
    System.out.println("##########");
  }

  /**
   * This method decrypts the data. It reuses the PKCS#11 cipher engine for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If decryption fails for some reason.
   */
  public void decryptDataAgain() throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("testing cipher reuse... ");

    // test reuse of cipher object
    byte[] recoveredPlainText2 = decryptionEngine_.doFinal(cipherText_);
    ComparableByteArray recoveredData2 = new ComparableByteArray(recoveredPlainText2);
    ComparableByteArray originalData = new ComparableByteArray(DATA);
    if (recoveredData2.equals(originalData)) {
      System.out.println("SUCCESS");
    } else {
      System.out.println("FAILURE");
      throw new IAIKPkcs11Exception(
          "Decryption Engine reuse error: decrypted and original data mismatch");
    }

    System.out.println("##########");
  }

}
