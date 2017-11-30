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
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.provider.ComparableByteArray;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.ciphers.PKCS11UnwrapKeySpec;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;
import demo.pkcs.pkcs11.provider.utils.KeyTemplateDemo;

/**
 * This class shows a short demonstration of how to use this provider implementation for wrapping
 * secret keys. Most parts are identical to applications using other providers. The only difference
 * is the treatment of keystores and the key template for the unwrapped key.
 */
public class KeyWrapDemo {

  /**
   * The data that will be encrypted. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be encrypted.".getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The encryption/decryption key, that will be wrapped and unwrapped.
   */
  protected SecretKey secretKey_;

  /**
   * The encrypted secret key.
   */
  protected byte[] wrappedKey_;

  /**
   * The key to wrap and unwrap the secret key.
   */
  protected Key wrappingKey_;

  /**
   * This is the encrypted data.
   */
  protected byte[] cipherText_;

  /**
   * The decryption cipher engine.
   */
  protected Cipher decryptionEngine_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public KeyWrapDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    KeyWrapDemo demo = new KeyWrapDemo();

    String cipherAlgorithm = "AES";
    String wrappingAlgorithm = "AES";

    if (args.length == 1) {
      cipherAlgorithm = args[0];
      wrappingAlgorithm = args[0];
    } else if (args.length > 1) {
      cipherAlgorithm = args[0];
      wrappingAlgorithm = args[1];
    }

    demo.getOrGenerateKeys(cipherAlgorithm, wrappingAlgorithm);
    demo.encryptData(cipherAlgorithm);
    demo.wrapKey(wrappingAlgorithm);
    demo.unwrapKey(cipherAlgorithm, wrappingAlgorithm);
    demo.decryptData(cipherAlgorithm);

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a secret session key for encryption (<code>secretKey_</code>) and tries
   * to find a wrapping key on a token. If there is none, this method generates a temporary wrapping
   * key and stores it in the member variables <code>wrappingKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If initializing the key store fails.
   */
  public void getOrGenerateKeys(String cipherAlgorithm, String wrappingAlgorithm)
      throws GeneralSecurityException, IOException {
    iaik.pkcs.pkcs11.objects.SecretKey secretKeyTemplate = KeyTemplateDemo
        .getCipherSecretKeyTemplate(cipherAlgorithm);
    // set this key extractable, otherwise it can't be wrapped (i.e. extracted from the token)
    secretKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
    secretKey_ = KeyFinder.generateSecretKey(pkcs11Provider_, cipherAlgorithm,
        secretKeyTemplate);

    try {
      wrappingKey_ = KeyFinder.findWrappingSecretKey(pkcs11Provider_, wrappingAlgorithm);
    } catch (KeyException e) {
      wrappingKey_ = KeyFinder.generateWrappingSecretKey(pkcs11Provider_,
          wrappingAlgorithm);
    }
  }

  /**
   * This method encrypts the data. The ciphertext will later be decrypted with the unwrapped key.
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
   * This method wraps the <code>secretKey_</code> with the <code>wrappingKey_</code> and saves the
   * encrypted key to <code>wrappedKey_</code>.
   * 
   * @param wrappingAlgorithm
   *          the algorithm used to wrap the encryption key
   * @throws GeneralSecurityException
   *           if wrapping fails
   */
  public void wrapKey(String wrappingAlgorithm) throws GeneralSecurityException {
    System.out.println("##########");
    System.out.println("Wrapping used secret key.");

    System.out.print("wrapping... ");

    // get a cipher object from the PKCS#11 provider for wrapping
    Cipher encryptionEngine = Cipher.getInstance(wrappingAlgorithm + "/CBC/PKCS5Padding",
        pkcs11Provider_.getName());

    // create the initialization vector parameters
    int blocksize = encryptionEngine.getBlockSize();
    AlgorithmParameterSpec algorithmParameters = getAlgorithmParameters(
        wrappingAlgorithm, blocksize);

    // initialize for wrapping with the wrapping key
    encryptionEngine.init(Cipher.WRAP_MODE, wrappingKey_, algorithmParameters);

    // wrap the secret key
    wrappedKey_ = encryptionEngine.wrap(secretKey_);

    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * This method unwraps the <code>wrappedKey_</code> with the <code>wrappingKey_</code> and saves
   * the received secret key to <code>secretKey_</code>.
   * 
   * @param unwrappedKeyAlgorithm
   *          the key type of the wrapped key
   * @param wrappingAlgorithm
   *          the algorithm for unwrapping the key
   * @throws GeneralSecurityException
   *           if unwrapping fails
   */
  public void unwrapKey(String unwrappedKeyAlgorithm, String wrappingAlgorithm)
      throws GeneralSecurityException {
    System.out.println("##########");
    System.out.println("Unwrapping used secret key.");

    System.out.print("unwrapping... ");

    // get a cipher object from the PKCS#11 provider for unwrapping
    Cipher encryptionEngine = Cipher.getInstance(wrappingAlgorithm + "/CBC/PKCS5Padding",
        pkcs11Provider_.getName());

    // create the initialization vector parameters
    int blocksize = encryptionEngine.getBlockSize();
    IvParameterSpec algorithmParameters = getAlgorithmParameters(wrappingAlgorithm,
        blocksize);

    // also specify some details for the unwrapped key object
    iaik.pkcs.pkcs11.objects.SecretKey keyTemplate = KeyTemplateDemo
        .getCipherSecretKeyTemplate(unwrappedKeyAlgorithm);

    PKCS11UnwrapKeySpec params = new PKCS11UnwrapKeySpec(keyTemplate, algorithmParameters);

    // initialize for unwrapping with the unwrapping key
    encryptionEngine.init(Cipher.UNWRAP_MODE, wrappingKey_, params);

    // unwrap the secret key
    secretKey_ = (SecretKey) encryptionEngine.unwrap(wrappedKey_, unwrappedKeyAlgorithm,
        Cipher.SECRET_KEY);

    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * This method decrypts the previously encrypted data, to test the correctness of the unwrapped
   * key.
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

    // decrypt the data
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

  private IvParameterSpec getAlgorithmParameters(String algorithm, int blocksize) {
    IvParameterSpec specs;
    byte[] iv = new byte[blocksize]; // for testing, an all-zero IV is ok
    specs = new IvParameterSpec(iv);
    return specs;
  }

}
