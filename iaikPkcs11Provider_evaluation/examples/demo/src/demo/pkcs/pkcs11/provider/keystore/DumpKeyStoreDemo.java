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

package demo.pkcs.pkcs11.provider.keystore;

// class and interface imports
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;

/**
 * This class demonstrates how to read all entries of the PKCS#11 key store.
 */
public class DumpKeyStoreDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public DumpKeyStoreDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);

  }

  public static void main(String[] args) throws GeneralSecurityException, IOException {
    DumpKeyStoreDemo demo = new DumpKeyStoreDemo();

    demo.dumpKeyStore();

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method lists all contents of the PKCS#11 key store.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void dumpKeyStore() throws GeneralSecurityException, IOException {
    // with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
    // specific IAIKPkcs11 provider instance after this call, even if you specify the provider
    // at this call. this is a limitation of SUN's KeyStore concept. the KeyStoreSPI object
    // has no chance to get its own provider instance.
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");

    if (tokenKeyStore == null) {
      System.out
          .println("Got no key store. Ensure that the provider is properly configured and installed.");
      throw new KeyStoreException("got no key store");
    }
    tokenKeyStore.load(null, null); // this call binds the keystore to the first instance of the
                                    // IAIKPkcs11 provider
    // if you want ot bind it to a different instance, you have to provide the provider name as
    // stream
    // see the other RSASigningDemo classes for examples

    // tokenKeyStore.load(new ByteArrayInputStream(pkcs11Provider_.getName().getBytes("UTF-8")),
    // null);

    Enumeration aliases = tokenKeyStore.aliases();

    // and we take the first signature (private) key for simplicity
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement().toString();

      if (tokenKeyStore.isKeyEntry(alias)) {
        System.out
            .println("________________________________________________________________________________");
        System.out.println("Key entry with alias: " + alias);
        Key key = tokenKeyStore.getKey(alias, null);
        System.out.println(key);
        Certificate[] certificateChain = tokenKeyStore.getCertificateChain(alias);
        if (certificateChain != null) {
          System.out.println("Certificate chain of length: " + certificateChain.length);
          for (int i = 0; i < certificateChain.length; i++) {
            System.out
                .println("--------------------------------------------------------------------------------");
            System.out.println(certificateChain[i]);
          }
        } else {
          System.out.println("Certificate chain is null!");
        }
        System.out
            .println("________________________________________________________________________________");
      } else if (tokenKeyStore.isCertificateEntry(alias)) {
        System.out
            .println("________________________________________________________________________________");
        System.out.println("Certificate entry with alias: " + alias);
        Certificate certificate = tokenKeyStore.getCertificate(alias);
        System.out.println(certificate);
        System.out
            .println("________________________________________________________________________________");
      } else {
        System.out
            .println("________________________________________________________________________________");
        System.out.println("ERROR! Unknown entry type with alias: " + alias);
        System.out
            .println("________________________________________________________________________________");
      }
    }
  }

}
