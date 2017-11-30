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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;

/**
 * Signs a X.509 certificate using a token. The actual X.509 specific operations are in the last
 * section of this demo. The hash is calculated outside the token. This implementation just uses raw
 * RSA.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SignCertificate {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The certificate.
   */
  protected X509Certificate certificate_;

  /**
   * The certificate request.
   */
  protected CertificateRequest certificateRequest_;

  /**
   * The name of the signed file.
   */
  protected OutputStream output_;

  /**
   * The key store that represents the token (smart card) contents.
   */
  protected KeyStore tokenKeyStore_;

  /**
   * The signature key. In this case only a proxy object, but the application cannot see this.
   */
  protected PrivateKey signatureKey_;

  /**
   * The certificate of the signature key - the issuer certificate.
   */
  protected X509Certificate issuerCertificate_;

  /**
   * path to safe issuer's certificate (optional).
   */
  protected String issuerCertificatePath_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public SignCertificate(CertificateRequest certificateRequest, String issuerOutputFile,
      OutputStream output) {
    certificateRequest_ = certificateRequest;
    issuerCertificatePath_ = issuerOutputFile;
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
    if (args.length < 2) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }
    String certificateRequestFile = args[0];
    String outputFile = args[1];
    String issuerOutputFile = (args.length > 2) ? args[2] : null;

    CertificateRequest certificateRequest = new CertificateRequest(new FileInputStream(
        certificateRequestFile));
    OutputStream output = new FileOutputStream(outputFile);

    SignCertificate demo = new SignCertificate(certificateRequest, issuerOutputFile,
        output);

    demo.getSignatureKey();
    demo.prepareCertificate();
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
    KeyAndCertificate keyAndCert = Util.getSignatureKeyAndCert(pkcs11Provider_, false);
    signatureKey_ = keyAndCert.getPrivateKey();
    issuerCertificate_ = keyAndCert.getCertificateChain()[0];
  }

  /**
   * Gets the information out of the certificate request and merges it into the certificate
   * template.
   * 
   * @exception GeneralSecurityException
   *              If the public key type is unsupported.
   */
  public void prepareCertificate() throws GeneralSecurityException {
    certificate_ = createPlainCertificate();
    certificate_.setIssuerDN(issuerCertificate_.getSubjectDN());

    certificate_.setSubjectDN(certificateRequest_.getSubject());
    certificate_.setPublicKey(certificateRequest_.getPublicKey());
  }

  /**
   * This method signs the certificate with the private key in the PKCS#11 module.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If the data file could not be found.
   */
  public void sign() throws GeneralSecurityException, IOException {
    System.out.println("##########");

    System.out.print("signing certificate... ");
    certificate_.sign(AlgorithmID.sha1WithRSAEncryption, signatureKey_,
        pkcs11Provider_.getName());
    System.out.println("finished");

    System.out.print("writing DER-encoded certificate to file... ");
    certificate_.writeTo(output_);
    System.out.println("finished");

    if (issuerCertificatePath_ != null) {
      issuerCertificate_.writeTo(new FileOutputStream(issuerCertificatePath_));
    }

    System.out.println("##########");
  }

  /**
   * This method verifies the signature of the certificate. This is done in pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If reading the PKCS#7 file fails.
   */
  public void verify() throws GeneralSecurityException, IOException {
    System.out.println("##########");

    System.out.print("verifying certificate... ");

    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    certificate_.writeTo(buffer);

    InputStream inputStream = new ByteArrayInputStream(buffer.toByteArray()); // the raw data
                                                                              // supplying input
                                                                              // stream
    X509Certificate certificate = new X509Certificate(inputStream);

    certificate.verify(issuerCertificate_.getPublicKey());

    System.out.println("finished");

    System.out.println("##########");
  }

  public X509Certificate createPlainCertificate() throws GeneralSecurityException {
    X509Certificate cert = new X509Certificate();

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

    return cert;
  }

  public static void printUsage() {
    System.out
        .println("Usage: SignCertificate <pkcs#10 certificate request> <DER-encoded X.509 certificate output file> [<DER-encoded X.509 certificate of issuer output file>]");
    System.out
        .println(" e.g.: SignCertificate certificateRequest.p10 issuedCertificate.cer issuerCertificate.cer");
  }

}
