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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.RSACipherProvider;
import iaik.pkcs.pkcs7.SignedDataStream;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;

/**
 * This class shows how to sign data according to PKCS#7 using the PKCS#11 provider. This
 * implementation uses the RSACipherProvider feature of the PKCS#7 implementation of the IAIK-JCE.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class PKCS7SigningDemoWithRSACipherProvider {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The name of the file that contains the data to be signed.
   */
  protected String fileToBeSigned_;

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
   * This is the certificate used for verifying the signature. In contrast to the signature key,
   * this key holds the actual keying material.
   */
  protected X509Certificate signerCertificate_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public PKCS7SigningDemoWithRSACipherProvider(String fileToBeSigned, String outputFile) {
    fileToBeSigned_ = fileToBeSigned;
    outputFile_ = outputFile;

    // special care is required during the registration of the providers
    pkcs11Provider_ = new IAIKPkcs11();
    // IAIKPkcs11.insertProviderAtForJDK14(pkcs11Provider_, 1); // add IAIK PKCS#11 JCE provider as
    // first, use JDK 1.4 bug workaround

    iaikSoftwareProvider_ = new IAIK();
    Security.addProvider(iaikSoftwareProvider_); // add IAIK softweare JCE provider
    Security.addProvider(pkcs11Provider_);

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
    String fileToBeSigned = args[0];
    String outputFile = args[1];

    PKCS7SigningDemoWithRSACipherProvider demo = new PKCS7SigningDemoWithRSACipherProvider(
        fileToBeSigned, outputFile);

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
    signerCertificate_ = keyAndCert.getCertificateChain()[0];
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
  public void sign() throws GeneralSecurityException, IOException {
    System.out.println("##########");
    System.out.print("Signing data... ");

    InputStream dataStream = new FileInputStream(fileToBeSigned_); // the raw data supplying input
                                                                   // stream
    SignedDataStream signedData = new SignedDataStream(dataStream,
        SignedDataStream.IMPLICIT);
    iaik.x509.X509Certificate iaikSignerCertificate = (signerCertificate_ instanceof iaik.x509.X509Certificate) ? (iaik.x509.X509Certificate) signerCertificate_
        : new iaik.x509.X509Certificate(signerCertificate_.getEncoded());
    signedData.setCertificates(new iaik.x509.X509Certificate[] { iaikSignerCertificate });
    IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(
        signerCertificate_);
    SignerInfo signerInfo = new SignerInfo(issuerAndSerialNumber, AlgorithmID.sha1,
        signatureKey_);
    signerInfo
        .setRSACipherProvider(new RSACipherProvider(pkcs11Provider_.getName(), null));
    signedData.addSignerInfo(signerInfo);

    FileOutputStream outputStream = new FileOutputStream(outputFile_);
    signedData.writeTo(outputStream);
    outputStream.flush();
    outputStream.close();

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
    System.out.println("Verifying signature");

    InputStream inputStream = new FileInputStream(outputFile_); // the raw data supplying input
                                                                // stream
    SignedDataStream signedData = new SignedDataStream(inputStream);

    InputStream signedDataInputStream = signedData.getInputStream();

    byte[] buffer = new byte[4096];
    int bytesRead;
    while ((bytesRead = signedDataInputStream.read(buffer)) >= 0) {
      // do something useful wit the original data
    }

    // get the signer infos
    SignerInfo[] signerInfos = signedData.getSignerInfos();
    // verify the signatures
    for (int i = 0; i < signerInfos.length; i++) {
      try {
        // verify the signature for SignerInfo at index i
        X509Certificate signerCertificate = signedData.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "
            + signerCertificate.getSubjectDN());
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer: "
            + signedData.getCertificate(signerInfos[i].getIssuerAndSerialNumber())
                .getSubjectDN());
        throw ex;
      }
    }
    System.out.println("##########");
  }

  /**
   * Print information how to use this demo class.
   */
  public static void printUsage() {
    System.out
        .println("Usage: PKCS7SigningDemoWithRSACipherProvider <file to sign> <output file>");
    System.out
        .println(" e.g.: PKCS7SigningDemoWithRSACipherProvider contract.rtf signedContract.p7");
  }

}
