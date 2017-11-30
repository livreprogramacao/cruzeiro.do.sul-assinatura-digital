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

package demo.pkcs.pkcs11.provider.hashes;

// class and interface imports
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;

/**
 * This class shows a short demonstration of how to use this provider implementation for hashing.
 * Most parts are identical to applications using other providers.
 */
public class DigestDemo {

  /**
   * The data that will be hashed. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be hashed.".getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The message digest engine to create the hash value.
   */
  protected MessageDigest digestEngine_;

  /**
   * Here the actual hash value is stored.
   */
  protected byte[] hash_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public DigestDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException {
    DigestDemo demo = new DigestDemo();

    String algorithm = (args.length > 0) ? args[0] : "sha256";
    demo.hashData(algorithm);
    demo.verifyHash(algorithm);
    demo.hashDataAgain();

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method hashes the data in the byte array <code>DATA</code>. Normally the data would be
   * read from file. The calculated hash is stored in <code>hash_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void hashData(String algorithm) throws GeneralSecurityException {
    // Get a hash object from our new provider
    digestEngine_ = MessageDigest.getInstance(algorithm, pkcs11Provider_.getName());

    // put the data that should be signed
    System.out.println("##########");
    System.out.println("The data to be hashed is: \"" + new String(DATA) + "\"");
    System.out.println("##########");
    digestEngine_.update(DATA);

    // get the hash
    hash_ = digestEngine_.digest();
    System.out.println("##########");
    System.out.println("The hash is:");
    System.out.println(new BigInteger(1, hash_).toString(16));
    System.out.println("##########");
  }

  /**
   * This method verifies the hash stored in <code>hash_</code>. Here IAIK is used, IAIK is pure
   * software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifyHash(String algorithm) throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    MessageDigest digestEngine = MessageDigest.getInstance(algorithm, "IAIK");

    // put the original data that claims to be signed
    digestEngine.update(DATA);

    // verify the signature
    byte[] newHash = digestEngine.digest();

    System.out.println("##########");
    System.out.println("Trying to verify hash.");
    if (Arrays.equals(hash_, newHash)) {
      System.out.println("The hash was verified successfully.");
    } else {
      System.out.println("The two hashes are different. One of these two is wrong!");
      throw new IAIKPkcs11Exception("Hash verification error: hashes are different");
    }
    System.out.println("##########");
  }

  /**
   * This method hashes the data again. It reuses the PKCS#11 hash engine for this purpose.
   * 
   * @exception GeneralSecurityException
   *              If decryption fails for some reason.
   */
  public void hashDataAgain() throws GeneralSecurityException {
    System.out.println("##########");
    System.out.print("testing message digest engine reuse... ");

    digestEngine_.update(DATA);

    // get the hash
    byte[] hash = digestEngine_.digest();

    boolean verified = Arrays.equals(hash_, hash);

    if (verified) {
      System.out.println("SUCCESS");
    } else {
      System.out.println("FAILURE");
      throw new IAIKPkcs11Exception("Digest engine reuse error: hashes are different");
    }

    System.out.println("##########");
  }

}
