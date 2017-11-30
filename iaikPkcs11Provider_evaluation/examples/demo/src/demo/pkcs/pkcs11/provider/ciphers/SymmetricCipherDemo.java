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
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;

/**
 * This class shows a short demonstration of how to use this provider implementation for symmetric
 * encryption and decryption. Most parts are identical to applications using other providers. The
 * only difference is the treatment of keystores. Smart card keystores cannot be read from streams
 * in general.
 */
public class SymmetricCipherDemo {

  /**
   * The data that will be encrypted. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be encrypted.".getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The encryption/decryption key. In this case only a proxy object, but the application cannot see
   * the difference.
   */
  protected SecretKey secretKey_;

  /**
   * This is the encrypted data.
   */
  protected byte[] cipherText_;

  /**
   * The decrpytion cipher engine.
   */
  protected Cipher decryptionEngine_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public SymmetricCipherDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    SymmetricCipherDemo demo = new SymmetricCipherDemo();

    String algorithm = (args.length > 0) ? args[0] : "AES";
    demo.getOrGenerateKeyPair(algorithm);
    demo.encryptData(algorithm);
    demo.decryptData(algorithm);
    demo.decryptDataAgain();

    System.out.flush();
    System.err.flush();
  }

  /**
   * First, this method tries to find the required key on a token. If there is none, this method
   * generates a temporary secret key and stores it in the member variables <code>secretKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If initializing the key store fails.
   */
  public void getOrGenerateKeyPair(String algorithm) throws GeneralSecurityException,
      IOException {
    try {
      secretKey_ = KeyFinder.findCipherSecretKey(pkcs11Provider_, algorithm);
    } catch (KeyException e) {
      secretKey_ = KeyFinder.generateCipherSecretKey(pkcs11Provider_, algorithm);
    }
  }

  /**
   * This method encrypts the data. It uses the software provider for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If encryption fails for some reason.
   */
  public void encryptData(String algorithm) throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("Encrypting this data: \"");
    System.out.print(new String(DATA));
    System.out.println("\"");
    System.out.println();

    System.out.print("encrypting... ");

    // get a cipher object from the PKCS#11 provider for encryption
    Cipher encryptionEngine = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding",
        pkcs11Provider_.getName());

    // create the initialization vector parameters
    int blocksize = encryptionEngine.getBlockSize();
    AlgorithmParameterSpec algorithmParameters = getAlgorithmParameters(algorithm,
        blocksize);

    // initialize for encryption with the secret key
    encryptionEngine.init(Cipher.ENCRYPT_MODE, secretKey_, algorithmParameters);

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
  public void decryptData(String algorithm) throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("decrypting... ");

    // Get a cipher object from our new provider
    decryptionEngine_ = Cipher.getInstance(algorithm + "/CBC/PKCS5Padding",
        pkcs11Provider_.getName());

    // create the initialization vector parameters
    AlgorithmParameterSpec algorithmParameters = getAlgorithmParameters(algorithm,
        decryptionEngine_.getBlockSize());

    // initialize for decryption with our secret key
    decryptionEngine_.init(Cipher.DECRYPT_MODE, secretKey_, algorithmParameters);

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
          "Decryption engine reuse error: decrypted and original data mismatch");
    }

    System.out.println("##########");
  }

  private AlgorithmParameterSpec getAlgorithmParameters(String algorithm, int blocksize) {
    AlgorithmParameterSpec specs;
    byte[] iv = new byte[blocksize]; // for testing, an all-zero IV is ok
    if (algorithm.equalsIgnoreCase("RC2")) {
      specs = new RC2ParameterSpec(128, iv);
    } else {
      specs = new IvParameterSpec(iv);
    }
    return specs;
  }

}
