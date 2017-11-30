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

package iaik.pkcs.pkcs11.provider.ssl;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keyfactories.PKCS11KeySpec;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11Key;
import iaik.security.ssl.IaikProvider;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements the <code>SecurityProvider</code> interface of IAIK-SSL. It overrides the
 * default behavior of the <code>IaikProvider</code> in a way that enables the use of PKCS#11 keys
 * and the PKCS#11 provider.
 * 
 * @see SecurityProvider
 */
public class IaikPkcs11SecurityProviderIsasilk extends IaikProvider {

  private boolean symmetricCipherViaPkcs11_;

  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * Default Constructor. Tries to add the provider IAIK PKCS#11 provider.
   */
  public IaikPkcs11SecurityProviderIsasilk() {
    super();

    // look, if there is already a IAIKPkcs11 provider installed
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      if (providers[i] instanceof IAIKPkcs11) {
        pkcs11Provider_ = (IAIKPkcs11) providers[i];
        break;
      }
    }

    // if there is none, install one
    if (pkcs11Provider_ == null) {
      pkcs11Provider_ = new IAIKPkcs11();
      Security.addProvider(pkcs11Provider_);
    }

    java.security.Provider installedIaikPkcs11Provider = Security
        .getProvider(pkcs11Provider_.getName());
    if (installedIaikPkcs11Provider == null) {
      String msg = "Could not install IAIK PKCS#11 provider!";
      System.err.println(msg);
      throw new RuntimeException(msg);
    }
  }

  /**
   * Uses the given provider and tries to install it if it is not installed yet.
   */
  public IaikPkcs11SecurityProviderIsasilk(IAIKPkcs11 pkcs11Provider) {
    super();

    if (pkcs11Provider == null) {
      throw new NullPointerException("Argument \"pkcs11Provider\" must not be null.");
    }
    pkcs11Provider_ = pkcs11Provider;

    // ensure that the provider is also installed
    java.security.Provider installedIaikPkcs11Provider = Security
        .getProvider(pkcs11Provider_.getName());
    if (installedIaikPkcs11Provider == null) {
      String msg = "Could not install IAIK PKCS#11 provider!";
      System.err.println(msg);
      throw new RuntimeException(msg);
    }
  }

  /**
   * @return Returns <code>true</code> if symmetric software keys will be processed via PKCS#11.
   */
  public boolean isSymmetricCipherViaPkcs11() {
    return symmetricCipherViaPkcs11_;
  }

  /**
   * @param usePkcs11
   *          <code>true</code> to process symmetric software keys via PKCS#11.
   */
  public void setSymmetricCipherViaPkcs11(boolean usePkcs11) {
    this.symmetricCipherViaPkcs11_ = usePkcs11;
  }

  /**
   * Return an implementation for the requested algorithm from the IAIK provider. For more
   * documentation see the superclass SecurityProvider.
   */
  protected Signature getSignature(String algorithm, int mode, Key key,
      SecureRandom random) throws Exception {
    Signature signatureEngine;

    if (key instanceof IAIKPKCS11Key) {
      signatureEngine = Signature.getInstance(algorithm, ((IAIKPKCS11Key) key)
          .getTokenManager().getProvider().getName());
      if (mode == SIGNATURE_SIGN) {
        signatureEngine.initSign((PrivateKey) key);
      } else if (mode == SIGNATURE_VERIFY) {
        signatureEngine.initVerify((PublicKey) key);
      } // do nothing for SIGNATURE_NONE
    } else {
      signatureEngine = super.getSignature(algorithm, mode, key, random);
    }

    return signatureEngine;
  }

  /**
   * Return an implementation for the requested algorithm from the IAIK provider. For more
   * documentation see the superclass SecurityProvider.
   */
  protected Cipher getCipher(String algorithm, int mode, Key key,
      AlgorithmParameterSpec param, SecureRandom random) throws Exception {
    Cipher cipherEngine;

    // to get hardware acceleration for symmetric cipher, the software keys must be converted to
    // hardware keys
    if (symmetricCipherViaPkcs11_ && (key instanceof SecretKey)) {
      SecretKey pkcs11SecretKey = translateKey((SecretKey) key);
      cipherEngine = Cipher.getInstance(algorithm, pkcs11Provider_.getName());
      if (mode != CIPHER_NONE) {
        int cmode = (mode == CIPHER_ENCRYPT) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        cipherEngine.init(cmode, pkcs11SecretKey, param, random);
      }

      return cipherEngine;
    }

    if (key instanceof IAIKPKCS11Key) {
      if (algorithm.startsWith(ALG_CIPHER_RSA)) {
        algorithm = ALG_CIPHER_RSA;
      }
      cipherEngine = Cipher.getInstance(algorithm, ((IAIKPKCS11Key) key)
          .getTokenManager().getProvider().getName());
      if (mode != CIPHER_NONE) {
        int cmode = (mode == CIPHER_ENCRYPT) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        cipherEngine.init(cmode, key, param, random);
      }
    } else {
      cipherEngine = super.getCipher(algorithm, mode, key, param, random);
    }

    return cipherEngine;
  }

  /**
   * Translate the given secret key to a temporary secret key of the PKCS#11 provider.
   * 
   * @param key
   *          The secret key to translate.
   * @return The PKCS#11 secret key.
   * @throws NoSuchAlgorithmException
   *           If a secret key factory is unavailable for the required key algorithm.
   * @throws NoSuchProviderException
   *           If a required JCE provider has not been installed.
   * @throws InvalidKeySpecException
   *           If translating the key failed.
   * @preconditions (key <> null)
   * @postconditions (result <> null)
   */
  private SecretKey translateKey(SecretKey key) throws NoSuchAlgorithmException,
      NoSuchProviderException, InvalidKeySpecException {
    SecretKey secretKey = (SecretKey) key;
    String keyAlgorithm = secretKey.getAlgorithm();
    SecretKeyFactory softwareKeyFactory = SecretKeyFactory.getInstance(keyAlgorithm,
        "IAIK");
    SecretKeySpec secretKeySpec = (SecretKeySpec) softwareKeyFactory.getKeySpec(
        secretKey, SecretKeySpec.class);
    SecretKeyFactory pkcs11KeyFactory = SecretKeyFactory.getInstance(keyAlgorithm,
        pkcs11Provider_.getName());

    // set some PKCS#11 specific key attributes
    iaik.pkcs.pkcs11.objects.SecretKey pkcs11KeyTemplate = new iaik.pkcs.pkcs11.objects.SecretKey();
    pkcs11KeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    pkcs11KeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    pkcs11KeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // we don't want the key
                                                                 // permanently on the token

    PKCS11KeySpec pkcs11KeySpec = (PKCS11KeySpec) new PKCS11KeySpec(secretKeySpec,
        pkcs11KeyTemplate).setUseUserRole(false);

    return pkcs11KeyFactory.generateSecret(pkcs11KeySpec);
  }

  /**
   * Calculate the raw signature. The provided data to be signed is the data provided to the
   * underlying encryption scheme; e.g. RSA. Here, the data to be signed is the concatenation of the
   * MD5 and Sha-1 hashes.
   * 
   * @param algorithmName
   *          The algorithm name; e.g. ALG_CIPHER_RSA_SIGN.
   * @param dataToBeSigned
   *          This is the data input for the underlying crypto algorithm; e.g. the digest info
   *          object or the concatenation of the MD5 and Sha-1 hashes.
   * @param key
   *          The signature key.
   * @param random
   *          The random source to use, if random data is required.
   * @return The signature value.
   * @exception Exception
   *              If calculating the signature value fails.
   */
  /*
   * in version 3.06 of iSaSiLk and later, this method can be used protected byte[]
   * calculateRawSignature(String algorithmName, byte[] dataToBeSigned, PrivateKey key, SecureRandom
   * random) throws Exception { byte[] signature;
   * 
   * if (key instanceof IAIKPKCS11Key) { Signature rawSignatureEngine; if
   * (algorithmName.startsWith(ALG_CIPHER_RSA) || algorithmName.equals(ALG_CIPHER_RSA_ENCRYPT_SSL2))
   * { // modified SSLv2 padding not supported in IAIK PKCS#11 provider rawSignatureEngine =
   * Signature.getInstance("RawRSA/PKCS1", ((IAIKPKCS11Key)
   * key).getTokenManager().getProvider().getName()); } else { int slashIndex =
   * algorithmName.indexOf('/'); String rawSignatureName = algorithmName.substring(0, (slashIndex >=
   * 0) ? slashIndex : algorithmName.length()); rawSignatureEngine = Signature.getInstance("Raw" +
   * rawSignatureName, ((IAIKPKCS11Key) key).getTokenManager().getProvider().getName()); }
   * rawSignatureEngine.initSign(key, random); rawSignatureEngine.update(dataToBeSigned); signature
   * = rawSignatureEngine.sign(); } else { signature = super.calculateRawSignature(algorithmName,
   * dataToBeSigned, key, random); }
   * 
   * return signature ; }
   */

  /**
   * Verify the provided signature. The provided data to be signed is the data provided to the
   * underlying encryption scheme; e.g. RSA. Here, the data to be signed is the concatenation of the
   * MD5 and Sha-1 hashes.
   * 
   * @param algorithmName
   *          The algorithm name; e.g. ALG_CIPHER_RSA_VERIFY.
   * @param dataToBeSigned
   *          This is the data input for the underlying crypto algorithm; e.g. the digest info
   *          object or the concatenation of the MD5 and Sha-1 hashes.
   * @param signature
   *          The signature value to verify.
   * @param key
   *          The verification key.
   * @return True, if the signature value was verified, false otherwise.
   * @exception Exception
   *              If verifying the signature value fails.
   */
  /*
   * in version 3.06 of iSaSiLk and later, this method can be used protected boolean
   * verifyRawSignature(String algorithmName, byte[] dataToBeSigned, byte[] signature, PublicKey
   * key) throws Exception { boolean verified;
   * 
   * if (key instanceof IAIKPKCS11Key) { Signature rawSignatureEngine; if
   * (algorithmName.startsWith(ALG_CIPHER_RSA) || algorithmName.equals(ALG_CIPHER_RSA_ENCRYPT_SSL2))
   * { // modified SSLv2 padding not supported in IAIK PKCS#11 provider rawSignatureEngine =
   * Signature.getInstance("RawRSA/PKCS1", ((IAIKPKCS11Key)
   * key).getTokenManager().getProvider().getName()); } else { int slashIndex =
   * algorithmName.indexOf('/'); String rawSignatureName = algorithmName.substring(0, (slashIndex >=
   * 0) ? slashIndex : algorithmName.length()); rawSignatureEngine = Signature.getInstance("Raw" +
   * rawSignatureName, ((IAIKPKCS11Key) key).getTokenManager().getProvider().getName()); }
   * rawSignatureEngine.initVerify(key); rawSignatureEngine.update(dataToBeSigned); verified =
   * rawSignatureEngine.verify(signature); } else { verified =
   * super.verifyRawSignature(algorithmName, dataToBeSigned, signature, key); }
   * 
   * return verified ; }
   */

  /**
   * Return an instance of the default SecureRandom class set in
   * <CODE>iaik.security.random.SecRandom</CODE>. For more documentation see the superclass
   * SecurityProvider.
   */
  protected SecureRandom getSecureRandom() {
    SecureRandom randomGenerator;

    try {
      randomGenerator = SecureRandom.getInstance("PKCS11", pkcs11Provider_.getName());
    } catch (Exception ex) {
      // we cannot use pkcs#11 for generating random, use software
      randomGenerator = super.getSecureRandom();
    }

    return randomGenerator;
  }
}
