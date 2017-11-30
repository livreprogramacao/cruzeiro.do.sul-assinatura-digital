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
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import demo.pkcs.pkcs11.provider.utils.CreateOCSPResponse;
import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.CodingException;
import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.BasicOCSPResponse;
import iaik.x509.ocsp.OCSPException;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.UnknownResponseException;

/**
 * Signs a X.509 OCSP response using a token. The actual X.509 specific operations are in the last
 * section of this demo. The hash is calculated outside the token. This implementation just uses raw
 * RSA.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SignOCSPResponse {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The certificate response.
   */
  protected OCSPResponse response_;

  /**
   * The ocsp request to respond to
   */
  protected OCSPRequest request_;

  /**
   * The name of the signed file.
   */
  protected OutputStream output_;

  /**
   * The certificate of the responder who signs the response (optional).
   */
  protected X509Certificate responderCertificate_;

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
  public SignOCSPResponse(OCSPRequest ocspRequest, OutputStream output) {
    request_ = ocspRequest;
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
      throw new InvalidParameterException("invalid parameters");
    }
    OCSPRequest ocspRequest = new OCSPRequest(new FileInputStream(args[0]));
    String outputFile = args[1];

    OutputStream output = new FileOutputStream(outputFile);

    SignOCSPResponse demo = new SignOCSPResponse(ocspRequest, output);

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
    responderCertificate_ = keyAndCert.getCertificateChain()[0];
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

    response_ = CreateOCSPResponse.createOCSPResponse(request_,
        (request_.getCertifcates()[0]).getPublicKey(),
        new X509Certificate[] { responderCertificate_ });

    System.out.print("signing OCSP response... ");
    BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse) response_.getResponse();
    basicOCSPResponse.sign(AlgorithmID.sha1WithRSAEncryption, signatureKey_,
        pkcs11Provider_.getName());
    response_.setResponse(basicOCSPResponse);
    System.out.println("finished");

    System.out.print("writing DER-encoded OCSP response to file... ");
    response_.writeTo(output_);
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
   * @exception CodingException
   *              If handling the OCSP structure fails.
   * @exception UnknownResponseException
   *              If the OCSP response is of an unknown type.
   */
  public void verify() throws GeneralSecurityException, IOException, CodingException,
      UnknownResponseException {
    System.out.println("##########");
    System.out.print("verifying OCSP response... ");

    if (responderCertificate_ != null) {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      response_.writeTo(buffer);

      InputStream inputStream = new ByteArrayInputStream(buffer.toByteArray()); // the raw data
                                                                                // supplying input
                                                                                // stream
      OCSPResponse response = new OCSPResponse(inputStream);
      BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse) response.getResponse();
      basicOCSPResponse.verify(responderCertificate_.getPublicKey());

      System.out.println("finished");
    } else {
      System.out.println("Skipped. No responder certificate specified.");
    }

    System.out.println("##########");
  }

  public static void printUsage() {
    System.out
        .println("Usage: SignOCSPRequest <DER-encoded X.509 OCSP request file> <DER-encoded X.509 OCSP response output file>");
    System.out.println(" e.g.: SignOCSPRequest ocspRequest.der ocspResponse.der");
  }

}
