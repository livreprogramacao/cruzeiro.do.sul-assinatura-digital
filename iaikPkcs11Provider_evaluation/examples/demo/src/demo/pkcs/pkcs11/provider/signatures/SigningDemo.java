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

package demo.pkcs.pkcs11.provider.signatures;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;

/**
 * 
 */
public class SigningDemo {

  /**
   * The data that will be signed. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be signed.".getBytes();

  /**
   * A modified version of DATA. Used to ensure that signature does not verify with modified data.
   */
  protected final static byte[] MODIFIED_DATA = "That is some data to be signed."
      .getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The signature key. In this case only a proxy object, but the application cannot see this.
   */
  protected PrivateKey signatureKey_;

  /**
   * This is the key used for verifying the signature. In contrast to the signature key, this key
   * holds the actual keying material.
   */
  protected PublicKey verificationKey_;

  /**
   * The signature engine to create signatures.
   */
  protected Signature signatureEngine_;

  /**
   * Here the actual signature is stored compliant to PKCS#11
   */
  protected byte[] signature_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   * 
   * @param userPIN
   *          The user PIN of the token, if available. If this parameter is null, the provider will
   *          prompt the PIN on demand.
   */
  public SigningDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {

    SigningDemo demo = new SigningDemo();

    String algorithm = "RSA";
    String withhashString = "SHA1with";
    String verificationProviderName = "IAIK";
    if (args.length > 1) {
      algorithm = args[0];
      verificationProviderName = args[1];
    }

    demo.getSignatureKeyPair(algorithm, verificationProviderName);
    demo.signData(algorithm, withhashString);
    demo.verifySignature(algorithm, withhashString, verificationProviderName);
    demo.verifySignatureWithModifiedData(algorithm, withhashString,
        verificationProviderName);
    demo.verifyModifiedSignature(algorithm, withhashString, verificationProviderName);
    demo.signDataAgain(algorithm, withhashString, verificationProviderName);
    System.out.flush();
    System.err.flush();
  }

  /**
   * This method gets a key pair suitable for signatures. The keys are stored in the member
   * variables <code>signatureKey_ </code> and <code>verificationKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getSignatureKeyPair(String algorithm, String verificationProviderName)
      throws GeneralSecurityException, IOException {
    KeyPair keyPair;
    try {
      keyPair = KeyFinder.findSignatureKeyPair(pkcs11Provider_, algorithm);
    } catch (KeyException e) {
      keyPair = KeyFinder.generateSignatureKeyPair(pkcs11Provider_, algorithm);
    }
    signatureKey_ = keyPair.getPrivate();
    verificationKey_ = keyPair.getPublic();

  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with <code>signatureKey_</code>.
   * Normally the data would be read from file. The created signature is stored in
   * <code>signature_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void signData(String algorithm, String withhashString)
      throws GeneralSecurityException {
    // Get a signature object from our new provider
    signatureEngine_ = Signature.getInstance(withhashString + algorithm,
        pkcs11Provider_.getName());

    // initialize for signing with our signature key that we got from
    // the keystore
    signatureEngine_.initSign(signatureKey_);

    // put the data that should be signed
    System.out.println("##########");
    System.out.println("The data to be signed is: \"" + new String(DATA) + "\"");
    System.out.println("##########");
    signatureEngine_.update(DATA);

    // get the signature
    signature_ = signatureEngine_.sign();
    System.out.println("##########");
    System.out.println("The signature is:");
    System.out.println(new BigInteger(1, signature_).toString(16));
    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifySignature(String algorithm, String withhashString,
      String verificationProviderName) throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    Signature signatureEngine = Signature.getInstance(withhashString + algorithm,
        verificationProviderName);

    // initialize for verification with our verification key that we got from
    // the certificate
    signatureEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    signatureEngine.update(DATA);

    // verify the signature
    boolean verified = signatureEngine.verify(signature_);

    System.out.println("##########");
    System.out.println("Trying to verify signature with original data.");
    if (verified) {
      System.out.println("The signature was verified successfully");
    } else {
      System.out.println("The signature was forged or the data was modified!");
      throw new IAIKPkcs11Exception(
          "signature error - signature was not verified successfully");
    }
    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifySignatureWithModifiedData(String algorithm, String withhashString,
      String verificationProviderName) throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    Signature signatureEngine = Signature.getInstance(withhashString + algorithm,
        verificationProviderName);

    // initialize for verification with our verification key that we got from
    // the certificate
    signatureEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    signatureEngine.update(MODIFIED_DATA);

    // verify the signature
    boolean verified = signatureEngine.verify(signature_);

    System.out.println("##########");
    System.out.println("Trying to verify signature with modified data.");
    if (verified) {
      System.out
          .println("FAILURE - The signature with modified data was verified successfully.");
      throw new IAIKPkcs11Exception(
          "signature error - signature with modified data was verified successfully");
    } else {
      System.out.println("SUCCESS - The signature with modified data was not verified!");
    }
    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifyModifiedSignature(String algorithm, String withhashString,
      String verificationProviderName) throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    Signature signatureEngine = Signature.getInstance(withhashString + algorithm,
        verificationProviderName);

    // initialize for verification with our verification key that we got from
    // the certificate
    signatureEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    signatureEngine.update(DATA);

    // create a modified signature
    byte[] modifiedSignature = createModified(signature_);

    // verify the signature
    boolean verified = false;
    System.out.println("##########");
    System.out.println("Trying to verify modified signature.");
    try {
      verified = signatureEngine.verify(modifiedSignature);
    } catch (SignatureException ex) {
      verified = false;
    }

    if (verified) {
      System.out.println("FAILURE - The modified signature was verified successfully.");
      throw new IAIKPkcs11Exception(
          "signature error - modified signature was verified successfully");
    } else {
      System.out.println("SUCCESS - The modified signature was not verified!");
    }
    System.out.println("##########");
  }

  /**
   * This method signs the data again. It reuses the PKCS#11 signature engine for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If signing fails for some reason.
   */
  public void signDataAgain(String algorithm, String withhashString,
      String verificationProviderName) throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("testing signature engine reuse... ");

    // put the data that should be signed
    signatureEngine_.update(DATA);

    // get the signature
    byte[] signature = signatureEngine_.sign();

    // get a signature object from the software-only provider for verification
    Signature verificationEngine = Signature.getInstance(withhashString + algorithm,
        verificationProviderName);

    // initialize for verification with our verification key that we got from
    // the certificate
    verificationEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    verificationEngine.update(DATA);

    // verify the signature
    boolean verified = verificationEngine.verify(signature);

    if (verified) {
      System.out.println("SUCCESS");
    } else {
      System.out.println("FAILURE");
      throw new IAIKPkcs11Exception(
          "signature error - signature was not verified successfully");
    }

    System.out.println("##########");
  }

  /**
   * Create a modified version of the given data. This method returns the original byte array with
   * one randomly selected bit flipped.
   * 
   * @param originalData
   *          The original to create a modified version from. The original data is not modified.
   * @return The modified version of the given data.
   */
  public byte[] createModified(byte[] originalData) {
    if (originalData == null) {
      return null;
    }
    if (originalData.length == 0) {
      return new byte[0];
    }
    // create a positiv big integer
    BigInteger originalInteger = new BigInteger(1, originalData);
    // invert last bit
    BigInteger modifiedInteger = originalInteger.flipBit(0);

    return modifiedInteger.toByteArray();
  }
}
