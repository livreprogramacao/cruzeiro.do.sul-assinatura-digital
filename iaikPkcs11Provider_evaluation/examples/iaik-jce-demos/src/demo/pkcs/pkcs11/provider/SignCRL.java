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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.DistributionPoint;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.RevokedCertificate;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.CRLNumber;
import iaik.x509.extensions.IssuingDistributionPoint;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.ReasonCode;
import iaik.x509.extensions.SubjectKeyIdentifier;

/**
 * Signs a X.509 CRL using a token. The actual X.509 specific operations are in the last section of
 * this demo. The hash is calculated outside the token. This implementation just uses raw RSA.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SignCRL {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The CRL.
   */
  protected X509CRL crl_;

  /**
   * The name of the signed file.
   */
  protected OutputStream output_;

  /**
   * The isuer's certificate (optional).
   */
  protected X509Certificate issuerCertificate_;

  /**
   * The key store that represents the token (smart card) contents.
   */
  protected KeyStore tokenKeyStore_;

  /**
   * The signature key. In this case only a proxy object, but the application cannot see this.
   */
  protected PrivateKey signatureKey_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public SignCRL(OutputStream output) {
    output_ = output;

    // special care is required during the registration of the providers
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_); // add IAIK PKCS#11 JCE provider

    iaikSoftwareProvider_ = new IAIK();
    Security.addProvider(iaikSoftwareProvider_); // add IAIK softweare JCE provider

  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }

    String outputFile = args[0];

    OutputStream output = new FileOutputStream(outputFile);

    SignCRL demo = new SignCRL(output);

    demo.getSignatureKey();
    demo.sign();
    demo.verify();

    output.flush();
    output.close();
    System.out.flush();
    System.err.flush();
  }

  /**
   * This method gets the key stores of all inserted (compatible) smart cards and simply takes the
   * first key-entry. From this key entry it takes the private key and the certificate to retrieve
   * the public key from. The keys are stored in the member variables <code>signatureKey_
   * </code> and <code>verificationKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getSignatureKey() throws GeneralSecurityException, IOException,
      RFC2253NameParserException {
    KeyAndCertificate keyAndCert = Util.getSignatureKeyAndCert(pkcs11Provider_, true);
    signatureKey_ = keyAndCert.getPrivateKey();
    issuerCertificate_ = keyAndCert.getCertificateChain()[0];
  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with <code>signatureKey_</code>.
   * Normally the data would be read from file. The created signature is stored in
   * <code>signature_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If the data file could not be found.
   */
  public void sign() throws GeneralSecurityException, IOException, CodingException {
    System.out.println("##########");

    crl_ = createCRL();

    System.out.print("signing CRL... ");
    crl_.sign(signatureKey_, pkcs11Provider_.getName());
    System.out.println("finished");

    System.out.print("writing DER-encoded CRL to file... ");
    crl_.writeTo(output_);
    System.out.println("finished");

    System.out.println("##########");
  }

  public X509CRL createCRL() throws GeneralSecurityException, CodingException {

    GregorianCalendar gc = new GregorianCalendar();

    X509Certificate cert1 = createDummyCertificate();
    RevokedCertificate rc1 = new RevokedCertificate(cert1, gc.getTime());
    X509Certificate cert3 = createDummyCertificate();
    RevokedCertificate rc3 = new RevokedCertificate(cert3, gc.getTime());

    // first create the extensions of the revoked certificates

    // ReasonCode
    rc1.addExtension(new ReasonCode(ReasonCode.removeFromCRL));
    rc3.addExtension(new ReasonCode(ReasonCode.cessationOfOperation));

    X509CRL crl = new X509CRL();

    crl.setIssuerDN((Name) issuerCertificate_.getSubjectDN());

    crl.setThisUpdate(gc.getTime());
    gc.add(Calendar.WEEK_OF_YEAR, 1);
    crl.setNextUpdate(gc.getTime());
    crl.setSignatureAlgorithm(AlgorithmID.sha1WithRSAEncryption);

    crl.addCertificate(rc1);
    crl.addCertificate(rc3);

    // AuthorityKeyIdentifier
    AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
    authorityKeyIdentifier.setKeyIdentifier(new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1 });
    GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier,
        "http://ca.test.com/");
    authorityKeyIdentifier.setAuthorityCertIssuer(new GeneralNames(generalName));
    authorityKeyIdentifier.setAuthorityCertSerialNumber(new BigInteger("91698236"));
    crl.addExtension(authorityKeyIdentifier);

    // CRLNumber
    CRLNumber cRLNumber = new CRLNumber(BigInteger.valueOf(4234235));
    crl.addExtension(cRLNumber);

    // IssuingDistributionPoint
    GeneralNames distributionPointName = new GeneralNames(new GeneralName(
        GeneralName.uniformResourceIdentifier, "http://ca.iaik.com/crl/"));
    IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
    issuingDistributionPoint.setDistributionPointName(distributionPointName);
    issuingDistributionPoint.setCritical(true);
    issuingDistributionPoint.setOnlyContainsUserCerts(true);
    issuingDistributionPoint.setIndirectCRL(true);
    issuingDistributionPoint.setReasonFlags(DistributionPoint.keyCompromise
        | DistributionPoint.certificateHold | DistributionPoint.cessationOfOperation);
    crl.addExtension(issuingDistributionPoint);

    System.out.println(crl.toString(true));

    return crl;
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If reading the PKCS#7 file fails.
   */
  public void verify() throws GeneralSecurityException, IOException {
    System.out.println("##########");
    System.out.print("verifying CRL... ");

    if (issuerCertificate_ != null) {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      crl_.writeTo(buffer);

      InputStream inputStream = new ByteArrayInputStream(buffer.toByteArray()); // the raw data
                                                                                // supplying input
                                                                                // stream
      X509CRL crl = new X509CRL(inputStream);

      crl.verify(issuerCertificate_.getPublicKey());
      System.out.println("finished");
    } else {
      System.out.println("Skipped. No issuer certificate specified.");
    }

    System.out.println("##########");
  }

  public X509Certificate createDummyCertificate() throws GeneralSecurityException,
      CodingException {
    X509Certificate cert = new X509Certificate();

    Name subject = new Name();
    subject.addRDN(ObjectID.surName, "User");
    subject.addRDN(ObjectID.givenName, "Test");
    subject.addRDN(ObjectID.country, "AT");
    subject.addRDN(ObjectID.organization, "organization");
    subject.addRDN(ObjectID.organizationalUnit, "unit");

    cert.setSubjectDN(subject);
    cert.setIssuerDN(issuerCertificate_.getSubjectDN());

    GregorianCalendar date = new GregorianCalendar();

    // not before one hour ago
    date.add(Calendar.HOUR_OF_DAY, -1);
    cert.setValidNotBefore(date.getTime());

    date.add(Calendar.MONTH, 11);
    cert.setValidNotAfter(date.getTime());

    KeyUsage keyUsage = new KeyUsage();
    keyUsage.set(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
        | KeyUsage.keyCertSign | KeyUsage.cRLSign);
    cert.addExtension(keyUsage);

    SecureRandom random = SecureRandom.getInstance("SHA512PRNG-SP80090", "IAIK");
    byte[] serial = new byte[12];
    random.nextBytes(serial);
    BigInteger number = new BigInteger(serial);
    cert.setSerialNumber(number);

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
        pkcs11Provider_.getName());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    cert.setPublicKey(keyPair.getPublic());
    cert.addExtension(new SubjectKeyIdentifier(keyPair.getPublic()));

    cert.sign(AlgorithmID.sha1WithRSAEncryption, signatureKey_, pkcs11Provider_.getName());

    return cert;
  }

  public static void printUsage() {
    System.out.println("Usage: SignCRL <DER-encoded X.509 CRL output file>");
    System.out.println(" e.g.: SignCRL issuedCRL.crl");
  }

}
