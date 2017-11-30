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
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenKeyStore;
import iaik.utils.KeyAndCertificate;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyFinder;
import demo.pkcs.pkcs11.provider.utils.KeyTemplateDemo;

/**
 * This class shows a short demonstration of how to create a key pair and the related certificate
 * and add them as private key entry to the token keystore. Finally, the created key entry is
 * deleted again.
 */
public class CreateKeystoreEntryDemo {

  public final static int CIPHER = 1;
  public final static int SIGNATURE = 2;
  public final static int WRAPPING = 3;
  public final static int DERIVATION = 4;

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * PKCS#11 keystore of the PKCS#11 JCE provider.
   */
  protected TokenKeyStore tokenKeyStore_;

  /**
   * the private key, that is generated and added to keystore
   */
  protected PrivateKey privKey_;

  /**
   * the public key, that is generated and added to keystore with a PublicKey-certificate
   */
  protected PublicKey pubKey_;

  public CreateKeystoreEntryDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
    tokenKeyStore_ = pkcs11Provider_.getTokenManager().getKeyStore();
  }

  public static void main(String[] args) throws Exception {

    CreateKeystoreEntryDemo demo = new CreateKeystoreEntryDemo();
    String algorithm = (args.length > 0) ? args[0] : "RSA";
    int usage = SIGNATURE;
    if (args.length > 1) {
      usage = Integer.parseInt(args[1]);
    }
    demo.start(algorithm, usage);
  }

  public void start(String algorithm, int usage) throws Exception {

    // choose unique label
    String uniquelabel = findUniqueLabel(algorithm);
    generateKeyPair(algorithm, usage);
    addKeyEntrywithCertificate(uniquelabel, algorithm, new KeyPair(pubKey_, privKey_),
        privKey_, usage);
    printEntry(uniquelabel);
    deleteEntry(uniquelabel);
  }

  /**
   * This method generates a session key-pair. It stores the key-pair in the member variables
   * <code>privKey_</code> and <code>pubKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public String findUniqueLabel(String algorithm) throws GeneralSecurityException {
    int j = 1;
    boolean foundLabel = false;
    String uniquelabel = "";
    while (!foundLabel) {
      uniquelabel = algorithm + "KeystoreEntryDemo" + j;
      if (!tokenKeyStore_.isKeyEntry(uniquelabel)) {
        foundLabel = true;
      }
      j++;
    }
    return uniquelabel;
  }

  /**
   * This method generates a session key-pair. It stores the key-pair in the member variables
   * <code>privKey_</code> and <code>pubKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateKeyPair(String algorithm, int usage)
      throws GeneralSecurityException {

    System.out.print("Generating a " + algorithm + " key-pair...");
    iaik.pkcs.pkcs11.objects.PrivateKey privateKeyTemplate;
    iaik.pkcs.pkcs11.objects.PublicKey publicKeyTemplate;

    switch (usage) {
    case CIPHER:
      privateKeyTemplate = KeyTemplateDemo.getCipherPrivateKeyTemplate(algorithm);
      publicKeyTemplate = KeyTemplateDemo.getCipherPublicKeyTemplate(algorithm);
      break;
    case WRAPPING:
      privateKeyTemplate = KeyTemplateDemo.getWrappingPrivateKeyTemplate(algorithm);
      publicKeyTemplate = KeyTemplateDemo.getWrappingPublicKeyTemplate(algorithm);
      break;
    case DERIVATION:
      privateKeyTemplate = KeyTemplateDemo.getDerivationPrivateKeyTemplate(algorithm);
      publicKeyTemplate = KeyTemplateDemo.getDerivationPublicKeyTemplate(algorithm);
      break;
    default:// signature
      privateKeyTemplate = KeyTemplateDemo.getSignaturePrivateKeyTemplate(algorithm);
      publicKeyTemplate = KeyTemplateDemo.getSignaturePublicKeyTemplate(algorithm);
    }

    SecureRandom random = new SecureRandom();
    byte[] id = new byte[20];
    random.nextBytes(id);
    privateKeyTemplate.getId().setByteArrayValue(id);
    publicKeyTemplate.getId().setByteArrayValue(id);

    KeyPair keyPair = KeyFinder.generateKeyPair(pkcs11Provider_, algorithm,
        privateKeyTemplate, publicKeyTemplate);
    privKey_ = keyPair.getPrivate();
    pubKey_ = keyPair.getPublic();

  }

  /**
   * This method creates a corresponding certificate to the generated key-pair. Afterwards the
   * private key is added to the key-store with the created certificate.
   * 
   * @param label
   *          label used to add key entry
   * @throws GeneralSecurityException
   *           if provider errors occur
   * @throws CodingException
   *           if the keyIdentifier for the certificate can't be created
   */
  public KeyAndCertificate addKeyEntrywithCertificate(String label, String algorithm,
      KeyPair keystoreKeyPair, PrivateKey caKey, int usage)
      throws GeneralSecurityException, CodingException {
    X509Certificate cert = new X509Certificate();

    Name issuer = new Name();
    issuer.addRDN(ObjectID.country, "AT");
    issuer.addRDN(ObjectID.organization, "organization");
    issuer.addRDN(ObjectID.organizationalUnit, "unit");

    Name subject = new Name();
    subject.addRDN(ObjectID.surName, "User");
    subject.addRDN(ObjectID.givenName, label);
    subject.addRDN(ObjectID.country, "AT");
    subject.addRDN(ObjectID.organization, "organization");
    subject.addRDN(ObjectID.organizationalUnit, "unit");

    cert.setSubjectDN(subject);
    cert.setIssuerDN(issuer);

    GregorianCalendar date = new GregorianCalendar();

    // not before one hour ago
    date.add(Calendar.HOUR_OF_DAY, -1);
    cert.setValidNotBefore(date.getTime());

    date.add(Calendar.MONTH, 11);
    cert.setValidNotAfter(date.getTime());

    KeyUsage keyUsage = new KeyUsage();
    switch (usage) {
    case CIPHER:
      keyUsage.set(KeyUsage.dataEncipherment);
      break;
    case WRAPPING:
      keyUsage.set(KeyUsage.keyEncipherment);
      break;
    case DERIVATION:
      keyUsage.set(KeyUsage.keyAgreement);
      break;
    default:
      keyUsage.set(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
          | KeyUsage.keyCertSign | KeyUsage.cRLSign);
    }
    cert.addExtension(keyUsage);

    SecureRandom random = SecureRandom.getInstance("SHA512PRNG-SP80090", "IAIK");
    byte[] serial = new byte[12];
    random.nextBytes(serial);
    BigInteger number = new BigInteger(serial);
    cert.setSerialNumber(number);

    cert.setPublicKey(keystoreKeyPair.getPublic());
    cert.addExtension(new SubjectKeyIdentifier(keystoreKeyPair.getPublic()));

    cert.sign(getAlgorithmID(algorithm), caKey, pkcs11Provider_.getName());

    tokenKeyStore_.setKeyEntry(label, keystoreKeyPair.getPrivate(), null,
        new java.security.cert.X509Certificate[] { cert });
    return new KeyAndCertificate(keystoreKeyPair.getPrivate(),
        new X509Certificate[] { cert });
  }

  private AlgorithmID getAlgorithmID(String algorithm) {
    AlgorithmID algorithmID = null;
    if (algorithm.equalsIgnoreCase("RSA")) {
      algorithmID = AlgorithmID.sha1WithRSAEncryption;
    } else if (algorithm.equalsIgnoreCase("ECDSA")) {
      algorithmID = AlgorithmID.ecdsa_With_SHA1;
    } else if (algorithm.equalsIgnoreCase("DSA")) {
      algorithmID = AlgorithmID.dsaWithSHA;
    } else {
      System.out.println("algorithm not supported in this demo");
    }
    return algorithmID;
  }

  /**
   * This method prints information to the added key entry.
   * 
   * @param label
   *          label of the key entry that should be printed
   */
  public void printEntry(String label) throws KeyStoreException,
      NoSuchAlgorithmException, UnrecoverableKeyException {
    Key key = tokenKeyStore_.getKey(label, null);
    X509Certificate signerCertificate = (X509Certificate) tokenKeyStore_
        .getCertificate(label);
    System.out.println("##########");
    System.out.println("The alias of the key store entry is: " + label);
    System.out.println("##########");
    System.out.println("##########");
    System.out.println("The private key is: " + key.toString());
    System.out.println("##########");
    System.out.println("##########");
    System.out.println("The corresponding certificate is:");
    System.out.println(signerCertificate.toString());
    System.out.println("##########");
  }

  /**
   * Deleting the added key entry
   * 
   * @param label
   *          label of the key entry that should be deleted
   */
  public void deleteEntry(String label) throws GeneralSecurityException, CodingException,
      IOException {
    if (tokenKeyStore_.isKeyEntry(label))
      tokenKeyStore_.deleteEntry(label);
  }

}
