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

package demo.pkcs.pkcs11.provider.macs;

// class and interface imports
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;

/**
 * This class shows a short demonstration of how to use this provider implementation for MACing.
 * Most parts are identical to applications using other providers. The only difference is the
 * treatment of keystores. Smart card keystores cannot be read from streams in general.
 */
public class MacDemo {

  /**
   * The data that will be signed. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be MACed.".getBytes();

  /**
   * A modified version of DATA. Used to ensure that MAC does not verify with modified data.
   */
  protected final static byte[] MODIFIED_DATA = "That is some data to be MACed."
      .getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The signature key. In this case only a proxy object, but the application cannot see this.
   */
  protected SecretKey key_;

  /**
   * The MAC engine to create MACs.
   */
  protected Mac macEngine_;

  /**
   * Here the actual signature is stored compliant to PKCS#1
   */
  protected byte[] mac_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public MacDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   * @throws IOException
   * @throws GeneralSecurityException
   */
  public static void main(String[] args) throws GeneralSecurityException, IOException {
    MacDemo demo = new MacDemo();

    String algorithm = (args.length > 0) ? args[0] : "HMAC/MD5";

    demo.getOrGenerateKey();
    demo.macData(algorithm);
    demo.verifyMac(algorithm);
    demo.verifyMacWithModifiedData(algorithm);
    demo.verifyModifiedMac(algorithm);
    demo.macDataAgain(algorithm);

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
      key_ = KeyFinder.findSignatureSecretKey(pkcs11Provider_, "GenericSecret");
    } catch (KeyException e) {
      key_ = KeyFinder.generateSignatureSecretKey(pkcs11Provider_, "GenericSecret");
    }

  }

  /**
   * This method macs the data in the byte array <code>DATA</code> with <code>macKey_</code>.
   * Normally the data would be read from file. The created MAC value is stored in <code>mac_</code>
   * .
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void macData(String algorithm) throws GeneralSecurityException {
    // Get a MAC object from our new provider
    macEngine_ = Mac.getInstance(algorithm, pkcs11Provider_.getName());

    // initialize for signing with our MAC key that we got from
    // the keystore
    macEngine_.init(key_);

    // put the data that should be MACed
    System.out.println("##########");
    System.out.println("The data to be MACed is: \"" + new String(DATA) + "\"");
    System.out.println("##########");
    macEngine_.update(DATA);

    // get the MAC
    mac_ = macEngine_.doFinal();
    System.out.println("##########");
    System.out.println("The MAC is:");
    System.out.println(new BigInteger(1, mac_).toString(16));
    System.out.println("##########");
  }

  /**
   * This method verifies the MAC stored in <code>mac_
   * </code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifyMac(String algorithm) throws GeneralSecurityException {
    // get a MAC object for verification
    Mac macEngine = Mac.getInstance(algorithm, pkcs11Provider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    macEngine.init(key_);

    // put the original data that claims to be MACed
    macEngine.update(DATA);

    // calculate the MAC
    byte[] newMac = macEngine.doFinal();

    System.out.println("##########");
    System.out.println("Trying to verify MAC.");
    if (Arrays.equals(mac_, newMac)) {
      System.out.println("The MAC was verified successfully");
    } else {
      System.out.println("The MAC was forged or the data was modified!");
      throw new IAIKPkcs11Exception("MAC verification error");
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
  public void verifyMacWithModifiedData(String algorithm) throws GeneralSecurityException {
    // get a MAC object for verification
    Mac macEngine = Mac.getInstance(algorithm, pkcs11Provider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    macEngine.init(key_);

    // put the original data that claims to be MACed
    macEngine.update(MODIFIED_DATA);

    // calculate the MAC
    byte[] newMac = macEngine.doFinal();

    System.out.println("##########");
    System.out.println("Trying to verify MAC with modified data.");
    if (Arrays.equals(mac_, newMac)) {
      System.out.println("FAILURE - MAC of modified data was verified successfully");
      throw new IAIKPkcs11Exception(
          "MAC verification error - MAC of modified data was verified successfully");
    } else {
      System.out.println("SUCCESS - modified data have not been verified.");
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
  public void verifyModifiedMac(String algorithm) throws GeneralSecurityException {
    // get a MAC object for verification
    Mac macEngine = Mac.getInstance(algorithm, pkcs11Provider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    macEngine.init(key_);

    // put the original data that claims to be MACed
    macEngine.update(DATA);

    // calculate the MAC
    byte[] newMac = macEngine.doFinal();

    // create a modified MAC
    byte[] modifiedMac = createModified(mac_);

    System.out.println("##########");
    System.out.println("Trying to verify modified MAC.");
    if (Arrays.equals(modifiedMac, newMac)) {
      System.out.println("FAILURE - modified MAC was verified successfully");
      throw new IAIKPkcs11Exception(
          "MAC verification error - modified MAC was verified successfully");
    } else {
      System.out.println("SUCCESS - modified MAC has not been verified.");
    }
    System.out.println("##########");
  }

  /**
   * This method signs the data again. It reuses the PKCS#11 MAC engine for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If MACing fails for some reason.
   * 
   * 
   */
  public void macDataAgain(String algorithm) throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("testing MAC engine reuse... ");

    // feed in the same data
    macEngine_.update(DATA);

    // get the MAC
    byte[] mac = macEngine_.doFinal();

    // get a MAC object for verification
    Mac macVerificationEngine = Mac.getInstance(algorithm, pkcs11Provider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    macVerificationEngine.init(key_);

    // put the original data that claims to be MACed
    macVerificationEngine.update(DATA);

    // calculate the verification MAC
    byte[] verificationMac = macVerificationEngine.doFinal();

    boolean verified = Arrays.equals(mac, verificationMac);

    if (verified) {
      System.out.println("SUCCESS");
    } else {
      System.out.println("FAILURE");
      throw new IAIKPkcs11Exception(
          "MAC engine reuse error - MAC could not be verified successfully");
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
    BigInteger originalInteger = new BigInteger(1, originalData); // create a positiv big integer
    int selectedBit = new Random().nextInt(originalData.length * 8); // select one bit randomly
    BigInteger modifiedInteger = originalInteger.flipBit(selectedBit); // invert selected bit

    return modifiedInteger.toByteArray();
  }

}
