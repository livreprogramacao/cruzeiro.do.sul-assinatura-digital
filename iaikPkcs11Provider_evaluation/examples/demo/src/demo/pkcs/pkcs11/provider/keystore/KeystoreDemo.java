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

import iaik.asn1.CodingException;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenKeyStore;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;

/**
 * This class shows a short demonstration of how to use a token keystore, i.e. how to load a key
 * store and how to find the required keys .
 */
public class KeystoreDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * PKCS#11 keystore of the PKCS#11 JCE provider.
   */
  protected KeyStore tokenKeyStore_;

  protected PrivateKey privateKey_;
  protected PublicKey publicKey_;
  protected String alias_;

  public KeystoreDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException, IOException,
      TokenException, CodingException {

    KeystoreDemo demo = new KeystoreDemo();
    // wait until token is inserted in slot
    demo.waitForToken();
    // ensure that a suitable key pair is available for this demo
    demo.ensureKeyPair();

    // load keystore of type TokenKeyStore to configure additional settings
    // also show private objects automatically (onlyPublic = false)
    demo.loadIAIKKeystore(false);
    // or load java.security.keystore
    demo.loadJCEKeystore();
    // find e.g. signature key pair by checking key usage in certificate
    String alias = demo.findKeysWithCertificateAttributes();
    // or find e.g. signature key pair by checking key attributes
    demo.findKeysWithKeyAttributes();
    // this key pair was found
    demo.printKeyPair();
    // reset settings for next demo
    IAIKPkcs11.discardProviderInstance(demo.pkcs11Provider_);
    demo.pkcs11Provider_ = null;

    KeystoreDemo demo2 = new KeystoreDemo();
    // no automatic log-in
    demo2.loadIAIKKeystore(true);
    // only public objects in keystore
    if (demo2.findKeysWithCertificateAttributes() == null) {
      System.out.println("can't find private key as only public objects in keystore");
    }
    // request private key for the known alias - now keystore will log in
    demo2.getKeystoreEntryByAlias(alias);

    // this key pair was found for the alias
    demo2.printKeyPair();
  }

  public void waitForToken() throws TokenException {
    TokenManager tokenManager = pkcs11Provider_.getTokenManager();

    while (!tokenManager.isTokenPresent()) {
      System.out.println("No valid token present in slot. Please insert a valid token.");
      System.out.flush();
      tokenManager.waitForSlotEvent();
    }
  }

  public void ensureKeyPair() throws GeneralSecurityException, IOException,
      CodingException {
    try {
      KeyFinder.findSignatureKeyPair(pkcs11Provider_, "RSA");
    } catch (KeyException e) {
      CreateKeystoreEntryDemo entryDemo = new CreateKeystoreEntryDemo();
      entryDemo.generateKeyPair("RSA", CreateKeystoreEntryDemo.SIGNATURE);
      entryDemo.addKeyEntrywithCertificate("keystoreDemoEntry", "RSA", new KeyPair(
          entryDemo.pubKey_, entryDemo.privKey_), entryDemo.privKey_,
          CreateKeystoreEntryDemo.SIGNATURE);
    }
  }

  public void loadIAIKKeystore(boolean onlyPublic) {
    TokenKeyStore iaikKeyStore = pkcs11Provider_.getTokenManager().getKeyStore();

    // no pin entry until really necessary, only public objects will be in keystore at first
    iaikKeyStore.setReadProtectedKeyOnDemand(onlyPublic);
    tokenKeyStore_ = iaikKeyStore;

  }

  public void loadJCEKeystore() throws GeneralSecurityException, IOException {
    tokenKeyStore_ = KeyStore.getInstance("PKCS11KeyStore");
    String providerName = pkcs11Provider_.getName();
    ByteArrayInputStream providerNameInputStream = new ByteArrayInputStream(
        providerName.getBytes("UTF-8"));

    // load the keystore of the PKCS#11 provider given via input stream
    // you can specify the PIN if available, otherwise enter PIN via prompt or PIN pad
    tokenKeyStore_.load(providerNameInputStream, null);
  }

  public String findKeysWithCertificateAttributes() throws GeneralSecurityException {
    Enumeration aliases = tokenKeyStore_.aliases();

    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement().toString();
      if (tokenKeyStore_.isKeyEntry(alias)) {
        Key key = tokenKeyStore_.getKey(alias, null);

        // choose one of these conditions to check the algorithm
        if (key instanceof RSAPrivateKey
            || (key.getAlgorithm().equalsIgnoreCase("RSA") && key instanceof PrivateKey)) {

          // retrieve certificate to check key usage
          Certificate certificate = tokenKeyStore_.getCertificate(alias);
          if (certificate != null && certificate instanceof X509Certificate) {
            X509Certificate publicKeyCertificate = (X509Certificate) certificate;
            boolean[] keyUsage = publicKeyCertificate.getKeyUsage();
            // to use for signing and verifying check for digital signature or non-repudiation
            if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) {
              // found key pair
              privateKey_ = (PrivateKey) key;
              publicKey_ = publicKeyCertificate.getPublicKey();
              // or remember correct alias
              return alias;
            }
          }
        }
      }
    }
    return null;
  }

  public String findKeysWithKeyAttributes() throws GeneralSecurityException {
    Enumeration aliases = tokenKeyStore_.aliases();

    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement().toString();
      if (tokenKeyStore_.isKeyEntry(alias)) {
        Key key = tokenKeyStore_.getKey(alias, null);

        // choose one of these conditions to check the algorithm
        if (key instanceof RSAPrivateKey
            || (key.getAlgorithm().equalsIgnoreCase("RSA") && key instanceof PrivateKey)) {

          // check if we also have the related public key certificate to retrieve the public key
          Certificate certificate = tokenKeyStore_.getCertificate(alias);
          if (certificate != null) {

            // check key usage with key attributes
            IAIKPKCS11PrivateKey pkcs11PrivateKey = (IAIKPKCS11PrivateKey) key;
            iaik.pkcs.pkcs11.objects.PrivateKey wrapperPrivateKey = (iaik.pkcs.pkcs11.objects.PrivateKey) pkcs11PrivateKey
                .getKeyObject();
            if (wrapperPrivateKey.getSign().getBooleanValue().booleanValue()) {
              // found key pair, can be used for signatures
              privateKey_ = (PrivateKey) key;
              publicKey_ = certificate.getPublicKey();
              // or remember correct alias
              return alias;
            }
          }
        }
      }
    }

    return null;
  }

  public void getKeystoreEntryByAlias(String alias) throws GeneralSecurityException {
    privateKey_ = (PrivateKey) tokenKeyStore_.getKey(alias, null);
    Certificate cert = tokenKeyStore_.getCertificate(alias);
    if (cert != null) {
      publicKey_ = cert.getPublicKey();
    }
  }

  public void printKeyPair() throws KeyStoreException, NoSuchAlgorithmException,
      UnrecoverableKeyException {
    if (privateKey_ != null && publicKey_ != null) {
      System.out.println("##########");
      System.out.println("The private key is: ");
      System.out.println(privateKey_.toString());
      System.out.println("##########");
      System.out.println("The corresponding public key is:");
      System.out.println(publicKey_.toString());
      System.out.println("##########");
    } else {
      System.out.println("found no key pair");
    }
  }

}
