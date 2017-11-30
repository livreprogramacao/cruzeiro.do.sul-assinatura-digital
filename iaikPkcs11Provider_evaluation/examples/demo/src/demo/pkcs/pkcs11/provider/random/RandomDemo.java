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

package demo.pkcs.pkcs11.provider.random;

// class and interface imports
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.random.FIPS140Test;

/**
 * This class shows a short demonstration of how to use this provider implementation for random data
 * generation.
 */
public class RandomDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * Here is the actual random data stored.
   */
  protected byte[] randomData_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public RandomDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException {
    RandomDemo demo = new RandomDemo();

    demo.generateRandomData();
    demo.testRandomData();

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates some random data and stores it in <code>randomData_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateRandomData() throws GeneralSecurityException {
    // Get a secure random object from our new provider
    // attention! this method always links the secure random engine to the first IAIKPkcs11 provider
    // instance
    // SecureRandom randomGenerator = SecureRandom.getInstance("PKCS11"); // all random bytes from
    // the pkcs#11 module
    SecureRandom randomGenerator = SecureRandom.getInstance("PKCS11Seeded"); // onyl initial seed
                                                                             // from pkcs#11 module

    // you may provide the provider's name, but this makes no difference; it will nevertheless be
    // linked
    // to the first IAIKPkcs11 provider instance
    // SecureRandom randomGenerator = SecureRandom.getInstance("PKCS11", pkcs11Provider_.getName());

    // you may use this method, if you want to use a different provider instance
    // SecureRandom randomGenerator = new PKCS11Random(pkcs11Provider_);

    int length = 2500; // = 20000 bits for the FIPS 140 test

    // generate random data
    System.out.println("##########");
    System.out.print("Generating " + length + " bytes of random data... ");
    byte[] randomData = new byte[length];
    randomGenerator.nextBytes(randomData);
    randomData_ = randomData;
    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * This method tests the random data stored in <code>randomData_</code>. It uses the FIPS 140
   * test.
   */
  public void testRandomData() {
    FIPS140Test test = new FIPS140Test(new ByteArrayInputStream(randomData_));
    test.setDebugStream(System.out);

    test.startTests();
  }

}
