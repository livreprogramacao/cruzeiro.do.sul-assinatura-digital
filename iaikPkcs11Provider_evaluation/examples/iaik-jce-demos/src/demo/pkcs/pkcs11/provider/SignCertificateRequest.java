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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.PemOutputStream;
import iaik.utils.RFC2253NameParser;
import iaik.utils.RFC2253NameParserException;

/**
 * Signs a PKCS#10 certificate request using a token. The actual PKCS#10 specific operations are in
 * the last section of this demo. The hash is calculated outside the token. This implementation just
 * uses raw RSA.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SignCertificateRequest {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The public key of the user that should be included in the certificate.
   */
  protected PublicKey subjectPublicKey_;

  /**
   * The distinguished name of the subject.
   */
  protected String subjectDN_;

  /**
   * The name of the signed file.
   */
  protected String outputFile_;

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
  public SignCertificateRequest(String subjectDN, String outputFile) {
    subjectDN_ = subjectDN;
    outputFile_ = outputFile;

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
    if (args.length != 2) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }
    String subjectDN = args[0];
    String outputFile = args[1];

    SignCertificateRequest demo = new SignCertificateRequest(subjectDN, outputFile);

    demo.getSignatureKey();
    demo.sign();
    demo.verify();

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
    subjectPublicKey_ = keyAndCert.getCertificateChain()[0].getPublicKey();
  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with <code>signatureKey_</code>.
   * Normally the data would be read from file. The created signature is stored in
   * <code>signature_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception FileNotFoundException
   *              If the data file could not be found.
   */
  public void sign() throws RFC2253NameParserException, GeneralSecurityException,
      IOException {
    System.out.println("##########");

    System.out.print("signing certificate request... ");
    RFC2253NameParser subjectNameParser = new RFC2253NameParser(subjectDN_);
    Name subjectName = subjectNameParser.parse();

    CertificateRequest certificateRequest = new CertificateRequest(subjectPublicKey_,
        subjectName);

    certificateRequest.sign(AlgorithmID.sha1WithRSAEncryption, signatureKey_,
        pkcs11Provider_.getName());
    System.out.println("finished");

    System.out.print("writing certificate request to file \"");
    System.out.print(outputFile_);
    System.out.print("\"... ");
    String firstLine = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    String lastLine = "-----END NEW CERTIFICATE REQUEST-----";
    OutputStream certificateStream = new PemOutputStream(
        new FileOutputStream(outputFile_), firstLine, lastLine);
    certificateRequest.writeTo(certificateStream);
    certificateStream.flush();
    certificateStream.close();
    System.out.println("finished");

    System.out.println("##########");
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
   * @exception PKCSException
   *              If handling the PKCS#7 structure fails.
   */
  public void verify() throws GeneralSecurityException, IOException, PKCSException {
    System.out.println("##########");
    System.out.print("verifying certificate request... ");

    InputStream inputStream = new FileInputStream(outputFile_); // the raw data supplying input
                                                                // stream
    CertificateRequest certificateRequest = new CertificateRequest(inputStream);

    certificateRequest.verify();

    System.out.println("finished");
    System.out.println("##########");
  }

  public static void printUsage() {
    System.out
        .println("Usage: SignCertificateRequest <RFC2253 subject name> <PEM-encoded PKCS#10 certificate request output file>");
    System.out
        .println(" e.g.: SignCertificateRequest \"CN=Karl Scheibelhofer,O=IAIK,C=AT,EMAIL=karl.scheibelhofer@iaik.at\" certificateRequest.p10");
  }

}
