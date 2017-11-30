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

// class and interface imports
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keypairgenerators.PKCS11KeyPairGenerationSpec;
import iaik.security.provider.IAIK;
import iaik.utils.RFC2253NameParser;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * This class shows a short demonstration of how to use this provider implementation for RSA
 * key-pair generation and following creation of a self-signed certificate.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SelfSignedCertificate {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The subject DN to put in the new certificate.
   */
  protected String subjectDNString_;

  /**
   * The new key-pair.
   */
  protected KeyPair keyPair_;

  /**
   * The created certificate.
   */
  protected X509Certificate certificate_;

  /**
   * The name of the file where to write the X.509 DER encoded public key.
   */
  protected String outputFile_;

  /**
   * The alias of the new key entry in the keystore.
   */
  protected String alias_;

  /**
   * The newly created certificate will contain the same contents as the given certificate template
   * except the subject DN, issuer DN, the public key and the signature. The subject and issuer DN
   * in the certificate will be the same as the <code>subjectDN</code> parameter. The public key is
   * taken from the newly generated key-pair. The signature is calculated newly with the new private
   * key.
   * 
   * @param templateCertificate
   *          The certificate template to use for creating the new certificate.
   * @param subjectDN
   *          The subject's distinguished name as RFC 2253 string.
   * @param outputFile
   *          The name of the file for writing the certificate.
   * @param alias
   *          The alias for the new key in the keystore.
   */
  public SelfSignedCertificate(String subjectDN, String outputFile, String alias) {
    subjectDNString_ = subjectDN;
    outputFile_ = outputFile;
    alias_ = alias;

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
    if (args.length != 3) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }
    String subjectDN = args[0];
    String outputFile = args[1];
    String alias = args[2];

    SelfSignedCertificate demo = new SelfSignedCertificate(subjectDN, outputFile, alias);
    demo.generateKeyPair();
    demo.printKeyPair();
    demo.createCertificate();
    demo.verifyCertificate();
    demo.writeCertificate();
    demo.storeKeyAndCertificate();
    System.out.flush();
    System.err.flush();
  }

  public void setKeyPair(KeyPair keyPair) {
    keyPair_ = keyPair;
  }

  /**
   * This method generates a RSA key-pair. It stores the key-pair in the member variable
   * <code>keyPair_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateKeyPair() throws GeneralSecurityException {
    if (keyPair_ == null) {
      System.out.print("Generating a RSA key-pair...");

      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
          pkcs11Provider_.getName());

      // ensure unique key-certificate id
      SecureRandom random = SecureRandom.getInstance("SHA512PRNG-SP80090", "IAIK");
      byte[] id = new byte[20];
      random.nextBytes(id);

      RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
      privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
      privateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
      privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
      privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
      privateKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);
      privateKeyTemplate.getId().setByteArrayValue(id);

      RSAPublicKey publicKeyTemplate = new RSAPublicKey();
      publicKeyTemplate.getModulusBits().setLongValue(new Long(1024));
      byte[] publicExponentBytes = { 0x01, 0x00, 0x01 };
      publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
      publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
      publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
      publicKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);

      PKCS11KeyPairGenerationSpec keyPairGenerationSpec = (PKCS11KeyPairGenerationSpec) new PKCS11KeyPairGenerationSpec(
          publicKeyTemplate, privateKeyTemplate).setUseUserRole(true);

      keyPairGenerator.initialize(keyPairGenerationSpec);

      keyPair_ = keyPairGenerator.generateKeyPair();

      System.out.println(" finished");
    }
  }

  /**
   * This method prints the generated RSA key-pair (<code>keyPair_</code>).
   */
  public void printKeyPair() {
    System.out
        .println("################################################################################");
    System.out.println("The generated RSA key-pair is:");
    if (keyPair_ == null) {
      System.out.println("null");
    } else {
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Public key:");
      System.out.println(keyPair_.getPublic());
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Private key:");
      System.out.println(keyPair_.getPrivate());
    }
    System.out
        .println("################################################################################");
  }

  /**
   * This method creats the certificate and signs it with the private key in the PKCS#11 module.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If the data file could not be found.
   */
  public X509Certificate createCertificate() throws GeneralSecurityException,
      IOException, RFC2253NameParserException {
    System.out.println("##########");

    System.out.print("creating certificate... ");
    X509Certificate certificate = createPlainCertificate();
    Name subject = new RFC2253NameParser(subjectDNString_).parse();
    certificate.setSubjectDN(subject);
    certificate.setIssuerDN(subject);
    certificate.setPublicKey(keyPair_.getPublic());
    System.out.println("finished");

    System.out.print("signing certificate... ");
    certificate.sign(AlgorithmID.sha1WithRSAEncryption, keyPair_.getPrivate(),
        pkcs11Provider_.getName());
    certificate_ = certificate;
    System.out.println("finished");

    System.out.println("##########");
    return certificate_;
  }

  /**
   * This method verifies the signature of the certificate. This is done in pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If reading the PKCS#7 file fails.
   */
  public void verifyCertificate() throws GeneralSecurityException, IOException {
    System.out.println("##########");

    System.out.print("verifying certificate... ");

    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    certificate_.writeTo(buffer);

    InputStream inputStream = new ByteArrayInputStream(buffer.toByteArray()); // the raw data
                                                                              // supplying input
                                                                              // stream
    X509Certificate certificate = new X509Certificate(inputStream);

    certificate.verify(keyPair_.getPublic());

    System.out.println("finished");

    System.out.println("##########");
  }

  /**
   * This method writes the generated certificate to the output file in DER encoded X.509 format.
   */
  public void writeCertificate() throws IOException, CertificateException {
    System.out
        .println("################################################################################");
    if (certificate_ != null) {
      System.out.println("Write generated certificate key to: " + outputFile_);
      OutputStream certificateOutputStream = new FileOutputStream(outputFile_);
      certificateOutputStream.write(certificate_.getEncoded());
      certificateOutputStream.flush();
      certificateOutputStream.close();
    } else {
      System.out.println("no certificate, nothing to write to output file");
    }
    System.out
        .println("################################################################################");
  }

  /**
   * This method stores the generated private key together with the certificate on the token. The
   * alias is used to refer to it.
   * 
   * @throws KeyStoreException
   *           If getting a keystore instance or if setting the new key entry fails.
   */
  public void storeKeyAndCertificate() throws KeyStoreException,
      NoSuchAlgorithmException, CertificateException, IOException {
    System.out
        .println("################################################################################");
    System.out.println("store key and certificate on the token");

    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");
    tokenKeyStore.load(
        new ByteArrayInputStream(pkcs11Provider_.getName().getBytes("UTF-8")), null);
    tokenKeyStore.setKeyEntry(alias_, keyPair_.getPrivate(), null,
        new java.security.cert.X509Certificate[] { certificate_ });

    System.out
        .println("################################################################################");
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
    System.out.println(number);

    return cert;
  }

  public static void printUsage() {
    System.out.println("Usage: SelfSignedCertificate " + "<RFC 2253 subject DN> "
        + "<DER-encoded X.509 public RSA key output file> <alias>");
    System.out.println(" e.g.: SelfSignedCertificate "
        + "\"CN=Karl Scheibelhofer,OU=IAIK,C=AT\" " + "selfSignedCertificate.cer mykey");
  }

}
