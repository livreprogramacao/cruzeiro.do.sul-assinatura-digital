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
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Vector;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.KeyBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.utils.KeyAndCertificate;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

/**
 * This class demonstrates how to import keys and certificates from a PKCS#12 file. This demo also
 * works with other providers than with the PKCS#11 provider. However, it does not exploit all
 * features of PKCS#11. The AdvancedImportPKCS12 class shows such advanced usage.
 */
public class ImportPKCS12 {

  /**
   * The data that will be signed. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be signed.".getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * All bare private keys without a matching certificate.
   */
  protected Vector singlePrivateKeys_;

  /**
   * All private keys and their matching certificates
   */
  protected Vector privateKeysAndCertificates_;

  /**
   * All trusted certificates without a private key.
   */
  protected Vector trustedCertificates_;

  /**
   * The token keystore that we use to access the token.
   */
  protected KeyStore tokenKeyStore_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public ImportPKCS12() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);

  }

  public static void main(String[] args) throws Exception {

    if (args.length != 2) {
      printUsage();
      throw new Exception("missing arguments");
    }

    ImportPKCS12 demo = new ImportPKCS12();

    demo.readPKCS12(args[0], args[1]);
    demo.initializeKeyStore();
    //demo.importPrivateKeysWithCertificates();
    //demo.importTrustedCertificates();

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method reads the PKCS#12 data from the given file and decrypts it using the provided
   * password. The PKCS#12 object is stored in the member variable <code>pkcs12_</code>.
   * 
   * @param pkcs12FileName
   *          The file that contians the PKCS#12 data.
   * @param password
   *          The password that protects the PKCS#12 data.
   * @exception Exception
   *              If loading or decrypting the PKCS#12 file fails.
   */
  public void readPKCS12(String pkcs12FileName, String password) throws Exception {
    FileInputStream pkcs12InputStream = new FileInputStream(pkcs12FileName);
    PKCS12 pkcs12 = new PKCS12(pkcs12InputStream);
    pkcs12.decrypt(password.toCharArray());

    System.out.println("##########");
    System.out.println("PKCS#12 contents are:");
    System.out.println(pkcs12.toString());
    System.out.println("##########");

    Vector privateKeys = new Vector(2);
    KeyBag[] keyBags = pkcs12.getKeyBags();
    for (int i = 0; i < keyBags.length; i++) {
      PrivateKey privateKey = keyBags[i].getPrivateKey();
      privateKeys.add(privateKey);
    }

    Vector keyAndCertificates = new Vector(2);
    Vector certificates = new Vector(8);
    CertificateBag[] certificateBags = pkcs12.getCertificateBags();
    HashSet handledCertificates = new HashSet(certificateBags.length);

    // first handle private keys with their certificate chains
    for (int i = 0; i < certificateBags.length; i++) {
      X509Certificate x509Certificate = certificateBags[i].getCertificate();
      // do not handle the same certificate twice
      if (!handledCertificates.contains(x509Certificate)) {
        // check if this is a certificate that corresponds to a private key that we have
        for (int j = 0; j < privateKeys.size(); j++) {
          PrivateKey privateKey = (PrivateKey) privateKeys.get(j);
          if (corresponds(privateKey, x509Certificate)) {
            X509Certificate[] certificateChain = createChain(x509Certificate,
                certificateBags);
            KeyAndCertificate keyAndCertificate = new KeyAndCertificate(privateKey,
                certificateChain);
            privateKeys.remove(privateKey);
            keyAndCertificates.add(keyAndCertificate);
            handledCertificates.addAll(Arrays.asList(certificateChain));
          }
        }
      }
    }

    // take the rest of the certificates as trusted certificates
    for (int i = 0; i < certificateBags.length; i++) {
      X509Certificate x509Certificate = certificateBags[i].getCertificate();
      // do not handle the same certificate twice
      if (!handledCertificates.contains(x509Certificate)) {
        certificates.add(x509Certificate);
        handledCertificates.add(x509Certificate);
      }
    }

    System.out.println("##########");
    System.out.println("private keys with certificates are:");
    System.out.println(keyAndCertificates.toString());
    System.out.println("##########");

    System.out.println("##########");
    System.out.println("private keys without certificates are:");
    System.out.println(privateKeys.toString());
    System.out.println("##########");

    System.out.println("##########");
    System.out.println("trusted certificates are:");
    System.out.println(certificates.toString());
    System.out.println("##########");

    privateKeysAndCertificates_ = keyAndCertificates;
    singlePrivateKeys_ = privateKeys;
    trustedCertificates_ = certificates;
  }

  /**
   * Check, if the given certificate contains a public key that corresponds to the given private
   * key.
   * 
   * @param privateKey
   *          The private key.
   * @param certificate
   *          The certificate that holds the public key to match.
   * @return True, if the private key creates signature that can be verified with the public key in
   *         the certificate.
   * @exception Exception
   *              If anything fails.
   */
  protected boolean corresponds(PrivateKey privateKey, X509Certificate certificate)
      throws Exception {
    boolean corresponds;

    String privateKeyAlgorithm = privateKey.getAlgorithm();
    PublicKey publicKey = certificate.getPublicKey();
    String publicKeyAlgorithm = publicKey.getAlgorithm();
    if (privateKeyAlgorithm.equalsIgnoreCase(publicKeyAlgorithm)) {
      SecureRandom random = new SecureRandom();
      Signature signatureEngine;
      if (privateKeyAlgorithm.equalsIgnoreCase("RSA")) {
        signatureEngine = Signature.getInstance("SHA1withRSA");
      } else {
        signatureEngine = Signature.getInstance(privateKeyAlgorithm); // this may not work in all
                                                                      // cases
      }

      // simply try a sign and verify
      signatureEngine.initSign(privateKey, random);
      signatureEngine.update(DATA);
      byte[] signature = signatureEngine.sign();

      signatureEngine.initVerify(publicKey);
      try {
        signatureEngine.update(DATA);
        corresponds = signatureEngine.verify(signature);
      } catch (SignatureException ex) {
        corresponds = false;
      }
    } else {
      corresponds = false;
    }

    return corresponds;
  }

  /**
   * Create the certificate chain for the given user certificate using the certificates in the given
   * certificate bags.
   * 
   * @param userCertificate
   *          The user certificate.
   * @param certificateBags
   *          The certificate bags
   * @return The certificate chain. User certificate first. Contains at least the user certificate.
   */
  protected X509Certificate[] createChain(X509Certificate userCertificate,
      CertificateBag[] certificateBags) {
    if (userCertificate == null) {
      throw new NullPointerException("Argument \"userCertificate\" must not be null.");
    }
    if (certificateBags == null) {
      throw new NullPointerException("Argument \"certificateBags\" must not be null.");
    }

    X509Certificate[] certificateChain = CertificateBag.getCertificates(certificateBags);
    X509Certificate[] arrangedCertificateChain = Util.arrangeCertificateChain(
        certificateChain, false);

    return arrangedCertificateChain;
  }

  /**
   * This method instanciates and initializes the token keystore. The keystore object is stored in
   * <code>tokenKeyStore_</code>.
   * 
   * @exception Exception
   *              If creating or initializing the keystore fails.
   */
  public void initializeKeyStore() throws Exception {
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

    tokenKeyStore_ = tokenKeyStore;
  }

  /**
   * This method writes the private keys and the corresponding certificates to the token..
   * 
   * @exception Exception
   *              If anything with the provider fails.
   */
  public void importPrivateKeysWithCertificates() throws Exception {
    System.out.println("##########");
    System.out.print("importing private keys and certificates... ");
    for (int i = 0; i < privateKeysAndCertificates_.size(); i++) {
      KeyAndCertificate keyAndCertificate = (KeyAndCertificate) privateKeysAndCertificates_
          .get(i);
      X509Certificate[] x509UserCertificateChain = keyAndCertificate
          .getCertificateChain();
      PrivateKey privateKey = keyAndCertificate.getPrivateKey();
      String aliasBase;
      if ((x509UserCertificateChain != null) && (x509UserCertificateChain.length > 0)) {
        aliasBase = x509UserCertificateChain[0].getSubjectDN().toString();
      } else {
        aliasBase = "Private Key";
      }
      String alias = aliasBase;
      int j = 2;
      // ensure that we do not overwrite anything
      while (tokenKeyStore_.containsAlias(alias)) {
        // choose another alias
        alias = aliasBase + "(" + j + ")";
        j++;
      }
      tokenKeyStore_.setKeyEntry(alias, privateKey, null, x509UserCertificateChain);
      printKeyPair(alias, privateKey, tokenKeyStore_.getCertificate(alias));
    }
    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * This method imports all trusted certificates; i.e. all certificate in the pkcs#12 file that are
   * not corresponding to a private key.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void importTrustedCertificates() throws Exception {
    for (int i = 0; i < trustedCertificates_.size(); i++) {
      X509Certificate x509Certificate = (X509Certificate) trustedCertificates_.get(i);
      String aliasBase = x509Certificate.getSubjectDN().toString();
      String alias = aliasBase;
      int j = 2;
      // ensure that we do not overwrite anything
      while (tokenKeyStore_.containsAlias(alias)) {
        // choose another alias
        alias = aliasBase + "(" + j + ")";
        j++;
      }
      tokenKeyStore_.setCertificateEntry(alias, x509Certificate);
    }
  }

  /**
   * This method prints the generated pkcs#11 key-pair (<code>keyPair_</code>).
   */
  public void printKeyPair(String alias, PrivateKey privateKey, Certificate certificate) {
    System.out
        .println("################################################################################");
    System.out.println("The following entry with alias " + alias + " has been added:");
    System.out
        .println("________________________________________________________________________________");
    System.out.println("Private key:");
    System.out.println((privateKey != null) ? privateKey.toString() : "null");
    System.out
        .println("________________________________________________________________________________");
    System.out.println("Certificate:");
    System.out.println((certificate != null) ? certificate.toString() : "null");
    System.out
        .println("################################################################################");
  }

  public static void printUsage() {
    System.out.println("Usage: ImportPKCS12 <PKCS#12 file> <password for PKCS#12 file>");
    System.out.println(" e.g.: ImportPKCS12 mykeys.p12 password");
  }

}
