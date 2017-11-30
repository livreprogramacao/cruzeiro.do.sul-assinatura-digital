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
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.CertID;
import iaik.x509.ocsp.OCSPException;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.Request;

/**
 * Signs a X.509 OCSP request using a token. The actual X.509 specific operations are in the last
 * section of this demo. The hash is calculated outside the token. This implementation just uses raw
 * RSA.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SignOCSPRequest {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The certificate request.
   */
  protected OCSPRequest request_;

  /**
   * The name of the signed file.
   */
  protected OutputStream output_;

  /**
   * The certificate of the requestor who signs the request (optional).
   */
  protected X509Certificate requestorCertificate_;

  /**
   * The certificate, the status should be requested for.
   */
  protected X509Certificate[] requestedCertificateChain_;

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
  public SignOCSPRequest(X509Certificate requestedCert,
      X509Certificate requestedCertIssuer, OutputStream output) {
    requestedCertificateChain_ = new X509Certificate[] { requestedCert,
        requestedCertIssuer };
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
    if (args.length < 3) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }

    X509Certificate requestedCert = new X509Certificate(new FileInputStream(args[0]));
    X509Certificate requestedCertIssuer = new X509Certificate(
        new FileInputStream(args[1]));
    String outputFile = args[2];

    OutputStream output = new FileOutputStream(outputFile);

    SignOCSPRequest demo = new SignOCSPRequest(requestedCert, requestedCertIssuer, output);

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
    KeyAndCertificate keyAndCert = Util.getSignatureKeyAndCert(pkcs11Provider_, false);
    signatureKey_ = keyAndCert.getPrivateKey();
    requestorCertificate_ = keyAndCert.getCertificateChain()[0];
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
   * @exception OCSPException
   *              If handling the OCSP structure fails.
   */
  public void sign() throws GeneralSecurityException, IOException, OCSPException {
    System.out.println("##########");

    request_ = createOCSPRequest();

    System.out.print("signing OCSP request... ");
    request_.sign(AlgorithmID.sha1WithRSAEncryption, signatureKey_,
        pkcs11Provider_.getName());
    System.out.println("finished");

    System.out.print("writing DER-encoded OCSP request to file... ");
    request_.writeTo(output_);
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
   */
  public void verify() throws GeneralSecurityException, IOException {
    System.out.println("##########");
    System.out.print("verifying OCSP request... ");

    if (requestorCertificate_ != null) {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      request_.writeTo(buffer);

      InputStream inputStream = new ByteArrayInputStream(buffer.toByteArray()); // the raw data
                                                                                // supplying input
                                                                                // stream
      OCSPRequest request = new OCSPRequest(inputStream);

      request.verify(requestorCertificate_.getPublicKey());
      System.out.println("finished");
    } else {
      System.out.println("Skipped. No requestor certificate specified.");
    }

    System.out.println("##########");
  }

  public OCSPRequest createOCSPRequest() throws OCSPException, GeneralSecurityException {
    // Unsigned request without extensions
    ReqCert reqCert;
    // try {
    // issuer name
    Name issuerName = (Name) requestedCertificateChain_[1].getSubjectDN();
    // issuer key
    PublicKey issuerKey = requestedCertificateChain_[1].getPublicKey();
    // create the certID
    CertID certID = new CertID(AlgorithmID.sha1, issuerName, issuerKey,
        requestedCertificateChain_[0].getSerialNumber());
    reqCert = new ReqCert(ReqCert.certID, certID);
    // } catch (Exception ex) {
    // throw new OCSPException("Error creating cert id: " + ex.toString());
    // }

    if (reqCert == null) {
      throw new OCSPException("Cannot create ocsp request from null cert id!");
    }

    try {
      // create a single request for the target cert identified by the reqCert
      Request request = new Request(reqCert);

      // create the OCSPRequest
      OCSPRequest ocspRequest = new OCSPRequest();

      // set the requestList
      ocspRequest.setRequestList(new Request[] { request });

      // set the requestor name
      ocspRequest.setRequestorName(new GeneralName(GeneralName.directoryName,
          requestorCertificate_.getSubjectDN()));
      // include signing certificates
      ocspRequest.setCertificates(new X509Certificate[] { requestorCertificate_ });

      System.out.println("Request created:");
      System.out.println(ocspRequest.toString(true));

      return ocspRequest;

    } catch (Exception ex) {
      throw new OCSPException(ex.toString());
    }
  }

  public static void printUsage() {
    System.out
        .println("Usage: SignOCSPRequest <DER-encoded X.509 certificate> <certifiate of the requested cert's issuer> <DER-encoded X.509 OCSP request output file>");
    System.out
        .println(" e.g.: SignOCSPRequest requestedCertificate.cer reqCertIssuer.cer ocspRequest.der");
  }

}
