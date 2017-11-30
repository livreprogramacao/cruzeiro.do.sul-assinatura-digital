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

package demo.pkcs.pkcs11.provider;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSParsingException;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keypairgenerators.PKCS11KeyPairGenerationSpec;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.security.provider.IAIK;
import iaik.utils.RFC2253NameParser;
import iaik.utils.RFC2253NameParserException;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Vector;

/**
 * This demo shows how to use the PKCS#11 provider to run a simple CA. It can generate a new
 * key-pair and a self-signed CA certificate.
 * 
 * @author Karl Scheibelhofer
 */
public class DemoCa {

  public static void main(String[] args) throws Exception {

    if (args.length < 1) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }

    Collection caNames = listCaNames(null);

    System.out.println();
    System.out.println("List of available CAs: " + caNames);
    System.out.println();

    String caName = "DemoCA";
    DemoCa ca;
    if (caNames.contains(caName)) {
      // use existing CA
      ca = new DemoCa(caName, null);
    } else {
      // create new CA, with new key-pair and CA certificate
      ca = new DemoCa("OU=TestCA,OU=IAIK,O=Graz University of Technology,C=AT", caName,
          null);
    }
    System.out.println("Using CA " + ca.getName() + " with CA certificate: ");
    System.out.println(ca.getCertificate().toString(true));

    // issue an end-entity certificate
    X509Certificate eeCert = ca.issueCertificate(Util.readFile(args[0]));
    System.out.println();
    System.out.println("Issued certificate: ");
    System.out.println(eeCert.toString(true));
    System.out.println();

  }

  private static Collection listCaNames(char[] pin) throws GeneralSecurityException,
      IOException {
    init(pin);
    Vector names = new Vector();
    Enumeration aliasEnum = tokenKeyStore_.aliases();
    while (aliasEnum.hasMoreElements()) {
      String alias = (String) aliasEnum.nextElement();
      if (!tokenKeyStore_.isKeyEntry(alias))
        continue;
      Key key = tokenKeyStore_.getKey(alias, pin);
      X509Certificate cert = (X509Certificate) tokenKeyStore_.getCertificate(alias);
      if ((key instanceof IAIKPKCS11PrivateKey) && (cert instanceof X509Certificate)) {
        iaik.pkcs.pkcs11.objects.PrivateKey pkcs11PrivateKeyObject = (iaik.pkcs.pkcs11.objects.PrivateKey) ((IAIKPKCS11PrivateKey) key)
            .getKeyObject();
        if (!pkcs11PrivateKeyObject.getSign().getBooleanValue().booleanValue())
          continue;
        boolean[] keyUsage = cert.getKeyUsage();
        if (!((keyUsage == null) || keyUsage[5] || keyUsage[6]))
          continue;
        names.add(alias);
      }
    }
    return names;
  }

  private static IAIKPkcs11 p11provider_;

  private static KeyStore tokenKeyStore_;

  private static void init(char[] pin) throws GeneralSecurityException, IOException {
    if (p11provider_ == null) {
      IAIKPkcs11 pkcs11Provider = new IAIKPkcs11();
      Security.addProvider(pkcs11Provider); // add IAIK PKCS#11 JCE provider

      Security.addProvider(new IAIK()); // add IAIK softweare JCE provider
      p11provider_ = pkcs11Provider;
      tokenKeyStore_ = pkcs11Provider.getTokenManager().getKeyStore();
    }
  }

  private String name_;

  private IAIKPKCS11PrivateKey caKey_;

  private X509Certificate caCert_;

  private DemoCa(String subjectDN, String caName, char[] pin)
      throws GeneralSecurityException, IOException, CodingException,
      RFC2253NameParserException {
    init(pin);
    PublicKey publicKey = generateKeyPair(caName);
    Name subject = new RFC2253NameParser(subjectDN).parse();
    createCaCert(publicKey, subject);
    // use the label of the generated key as alias, this is the most robust solution
    String alias = new String(caKey_.getKeyObject().getLabel().getCharArrayValue());
    tokenKeyStore_.setKeyEntry(alias, caKey_, null, new X509Certificate[] { caCert_ });
    name_ = alias;
  }

  private DemoCa(String caName, char[] pin) throws GeneralSecurityException, IOException {
    init(pin);
    caKey_ = (IAIKPKCS11PrivateKey) tokenKeyStore_.getKey(caName, pin);
    caCert_ = (X509Certificate) tokenKeyStore_.getCertificate(caName);
    name_ = caName;
  }

  X509Certificate getCertificate() {
    return caCert_;
  }

  String getName() {
    return name_;
  }

  private PublicKey generateKeyPair(String name) throws GeneralSecurityException {
    // if an entry with this name exists, delete it first
    if (tokenKeyStore_.containsAlias(name)) {
      tokenKeyStore_.deleteEntry(name);
    }

    // generate a new random ID, with 128 bit it is practically impossible to get a clash
    byte[] id = new byte[16];
    SecureRandom rand = new SecureRandom();
    rand.nextBytes(id);

    RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
    privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getSignRecover().setBooleanValue(Boolean.FALSE);
    privateKeyTemplate.getDecrypt().setBooleanValue(Boolean.FALSE);
    privateKeyTemplate.getUnwrap().setBooleanValue(Boolean.FALSE);
    privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    privateKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);
    privateKeyTemplate.getLabel().setCharArrayValue(name.toCharArray());
    privateKeyTemplate.getId().setByteArrayValue(id);

    RSAPublicKey publicKeyTemplate = new RSAPublicKey();
    publicKeyTemplate.getModulusBits().setLongValue(new Long(1024));
    byte[] publicExponentBytes = { 0x01, 0x00, 0x01 };
    publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
    publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
    publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    publicKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);
    publicKeyTemplate.getLabel().setCharArrayValue(name.toCharArray());
    publicKeyTemplate.getId().setByteArrayValue(id);

    PKCS11KeyPairGenerationSpec keyPairGenerationSpec = (PKCS11KeyPairGenerationSpec) new PKCS11KeyPairGenerationSpec(
        publicKeyTemplate, privateKeyTemplate).setUseUserRole(true);

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
        p11provider_.getName());
    keyPairGenerator.initialize(keyPairGenerationSpec);

    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    caKey_ = (IAIKPKCS11PrivateKey) keyPair.getPrivate();

    return keyPair.getPublic();
  }

  private void createCaCert(PublicKey publicKey, Name subject)
      throws GeneralSecurityException, CodingException {
    iaik.x509.X509Certificate cert = new iaik.x509.X509Certificate();

    cert.setSerialNumber(BigInteger.ONE);
    cert.setSubjectDN(subject);
    cert.setIssuerDN(subject);
    cert.setPublicKey(publicKey);

    GregorianCalendar date = new GregorianCalendar();
    cert.setValidNotBefore(date.getTime()); // valid from now

    date.add(Calendar.YEAR, 3); // default validity is 3 years from now on
    cert.setValidNotAfter(date.getTime());

    BasicConstraints extBasicConstraints = new BasicConstraints(true, 1);
    extBasicConstraints.setCritical(true);
    cert.addExtension(extBasicConstraints);

    KeyUsage extKeyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign
        | KeyUsage.cRLSign);
    extKeyUsage.setCritical(true);
    cert.addExtension(extKeyUsage);

    SubjectKeyIdentifier extSubjectKeyIdentifier = new SubjectKeyIdentifier(publicKey);
    cert.addExtension(extSubjectKeyIdentifier);

    cert.sign(AlgorithmID.sha1WithRSAEncryption, caKey_, p11provider_.getName());

    caCert_ = cert;
  }

  private X509Certificate issueCertificate(byte[] pkcs10request)
      throws GeneralSecurityException, PKCSParsingException, CodingException {
    CertificateRequest cr = new CertificateRequest(pkcs10request);
    if (!cr.verify())
      throw new SignatureException("signature in certificate request is invalid");
    PublicKey publicKey = cr.getPublicKey();
    Name subject = cr.getSubject();

    iaik.x509.X509Certificate cert = new iaik.x509.X509Certificate();

    // in a real CA, we must ensure that we do not use the same serial twice, e.g. use a running
    // counter stored in a file
    BigInteger serial = new BigInteger(128, new SecureRandom());
    cert.setSerialNumber(serial);
    cert.setSubjectDN(subject);
    cert.setIssuerDN(caCert_.getSubjectDN());
    cert.setPublicKey(publicKey);

    GregorianCalendar date = new GregorianCalendar();
    cert.setValidNotBefore(date.getTime()); // valid from now

    date.add(Calendar.YEAR, 3); // default validity is 3 years from now on
    cert.setValidNotAfter(date.getTime());

    BasicConstraints extBasicConstraints = new BasicConstraints(false);
    cert.addExtension(extBasicConstraints);

    KeyUsage extKeyUsage = new KeyUsage(KeyUsage.digitalSignature);
    extKeyUsage.setCritical(true);
    cert.addExtension(extKeyUsage);

    SubjectKeyIdentifier ski = new SubjectKeyIdentifier(publicKey);
    cert.addExtension(ski);

    SubjectKeyIdentifier caSki = (SubjectKeyIdentifier) caCert_
        .getExtension(SubjectKeyIdentifier.oid);
    AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(caSki.get());
    cert.addExtension(aki);

    cert.sign(AlgorithmID.sha1WithRSAEncryption, caKey_, p11provider_.getName());

    return cert;
  }

  public static void printUsage() {
    System.out.println("Usage: DemoCa <PEM-encoded PKCS#10 certificate request file>");
    System.out.println(" e.g.: DemoCa certificateRequest.p10");
  }

}
