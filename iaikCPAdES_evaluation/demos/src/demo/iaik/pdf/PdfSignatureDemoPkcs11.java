// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2016 Stiftung Secure Information and
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

package demo.iaik.pdf;

import iaik.cms.CMSSignatureException;
import iaik.cms.SecurityProvider;
import iaik.cms.pkcs11.IaikPkcs11SecurityProvider;
import iaik.pdf.asn1objects.RevocationInfoArchival;
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.pdf.cmscades.OcspResponseUtil;
import iaik.pdf.cmscades.TimeStampTokenUtil;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.pdf.parameters.PadesBasicParameters;
import iaik.pdf.signature.ApprovalSignature;
import iaik.pdf.signature.PdfSignatureDetails;
import iaik.pdf.signature.PdfSignatureEngine;
import iaik.pdf.signature.PdfSignatureException;
import iaik.pdf.signature.PdfSignatureInstance;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.tsp.TspVerificationException;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.CertStatus;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.Properties;

/**
 * This demo shows how to use the PdfSignatureEngine together with the IAIK PKCS#11 provider. A
 * PKCS#11 token is used to sign the PDF. This engine should allow easy and flexible specification
 * of all kinds of parameters.
 */
public class PdfSignatureDemoPkcs11 {

  private IAIKPkcs11 pkcs11Provider_;
  private PrivateKey privKey_;
  private Certificate[] certChain_;

  /**
   * Default constructor. PKCS#11 module name will be read from static properties.
   */
  public PdfSignatureDemoPkcs11() {
    Security.addProvider(new IAIK());
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  /**
   * Constructor for specifying the name of the required PKCS#11 module.
   * 
   * @param moduleName
   *          the PKCS#11 module name
   */
  public PdfSignatureDemoPkcs11(String moduleName) {
    Security.addProvider(new IAIK());
    Properties properties = new Properties();
    // specify PKCS#11 module path if given
    properties.put("PKCS11_NATIVE_MODULE", moduleName);
    // you can use dynamic or static properties
    // properties.put("PKCS11_WRAPPER_PATH",
    // "/usr/iaik/lib/libpkcs11wrapper.so")
    // properties.put("SLOT_ID", "[1]");
    pkcs11Provider_ = new IAIKPkcs11(properties);
    Security.addProvider(pkcs11Provider_);
  }

  /**
   * Reads PKCS#11 key and certificate.
   * 
   * @throws GeneralSecurityException
   *           if PKCS#11 keystore can't be read
   * @throws IOException
   *           if PKCS#11 keystore can't be loaded
   * @throws PdfSignatureException
   *           if no suitable key was found
   */
  private void getKeyAndCerts()
      throws GeneralSecurityException, IOException, PdfSignatureException {

    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");
    ByteArrayInputStream providerNameInputStream = new ByteArrayInputStream(
        pkcs11Provider_.getName().getBytes("UTF-8"));
    tokenKeyStore.load(providerNameInputStream, null);

    Enumeration<String> aliases = tokenKeyStore.aliases();
    // we take the first (private) key for simplicity
    String usedAlias = "";
    while (aliases.hasMoreElements()) {
      String alias = aliases.nextElement().toString();
      if (tokenKeyStore.isKeyEntry(alias)) {
        Certificate[] certChain = tokenKeyStore.getCertificateChain(alias);
        Key key = tokenKeyStore.getKey(alias, null);
        if (certChain != null && certChain.length > 0 && key instanceof PrivateKey) {
          privKey_ = (PrivateKey) key;
          certChain_ = certChain;
          usedAlias = alias;
          break;
        }
      }
    }
    if (privKey_ == null || certChain_ == null) {
      throw new PdfSignatureException("no suitable key with certificate chain found!");
    }

    System.out.println("using key with label " + usedAlias);
  }

  /**
   * Configure signature engine to create the signed PDF document.
   * 
   * @param fileToBeSigned
   *          filename of PDF document to be signed
   * @param signedFilePath
   *          filename of the new signed PDF
   * @throws IOException
   *           if a file can't be read or written
   * @throws PdfSignatureException
   *           if errors during signing occur
   */
  private void signPdf(String fileToBeSigned, String signedFilePath)
      throws IOException, PdfSignatureException {
    System.out.println("signing the file " + fileToBeSigned
        + " and saving signed file to " + signedFilePath + ".");
    PdfSignatureInstance sigInst = PdfSignatureEngine.getInstance();

    // set parameters for subfilter adbe.pkcs7.detached, use detached false for
    // subfilter adbe.pkcs7.sha1
    // PadesBasicParameters params = new PadesBasicParameters(true);
    // set parameters for subfilter ETSI.CAdES.detached
    PadesBESParameters params = new PadesBESParameters();

    params.setDigestAlgorithm("SHA512");
    params.setSignatureReason("test");
    params.setSignatureLocation("Graz");
    params.setSignatureContactInfo("Max");

    // set OCSP-URL to include OCSP response as signed attribute in signature
    System.out.println("configuring signature engine to include a OCSP response.");
    try {
      params.setOcspUrl(OcspResponseUtil.getOcspUrl((X509Certificate) certChain_[0]));
    } catch (GeneralSecurityException e) {
      // only set OCSP URl if available
    }

    // set CRLs to include as signed attribute in signature
    CRL crl = null;
    try {
      crl = CadesSignature.getCRL((X509Certificate) certChain_[0]);
    } catch (CmsCadesException e) {
      // only set crl if extractable
    }
    if (crl != null) {
      CRL[] crls = new CRL[1];
      crls[0] = crl;
      System.out.println("configuring signature engine to include CRLs.");
      params.setCrls(crls);
    }

    // set timestamp authority to add timestamp as unsigned attribute in
    // signature
    System.out.println("configuring signature engine to include a timestamp.");
    String tsaUrl = null;
    for (int i = 0; i < certChain_.length; i++) {
      X509Certificate cert = (X509Certificate) certChain_[i];
      try {
        tsaUrl = TimeStampTokenUtil.getTsaUrl(cert);
      } catch (GeneralSecurityException e) {
        // in case of error just set default url
      }
      if (tsaUrl != null) {
        break;
      }
    }
    if (tsaUrl != null) {
      params.addSignatureTimestampProperties(tsaUrl, null, null, null);
    } else {
      params.addSignatureTimestampProperties("http://tsp.iaik.tugraz.at/tsp/TspRequest",
          null, null, null);
    }

    // tell CMS to use the PKCS#11 provider
    SecurityProvider.setSecurityProvider(new IaikPkcs11SecurityProvider(pkcs11Provider_));

    // initialize engine with path to original pdf (to be signed), private key
    // for signature creation,
    // certificates and parameters
    sigInst.initSign(fileToBeSigned, null, signedFilePath, privKey_, certChain_, params);

    System.out.println("signing to file " + signedFilePath + " ...");
    // create signed pdf using specified name
    sigInst.sign();
  }

  /**
   * Basic verification of given signed PDF document.
   * 
   * @param fileToBeVerified
   *          signed document to be verified
   * @throws IOException
   *           if the document can't be read
   * @throws PdfSignatureException
   *           if errors during verification occur
   * @throws CmsCadesException
   *           if the signature is invalid or certificates are revoked or missing
   * @throws TspVerificationException
   *           if timestamp is invalid
   * @throws CertificateException
   *           if signer certificate already expired
   */
  private void verifySignedPdf(String fileToBeVerified)
      throws IOException, PdfSignatureException, CmsCadesException, CMSSignatureException,
      TspVerificationException, CertificateException {

    System.out.println("verifying file " + fileToBeVerified + " ... ");

    PdfSignatureInstance sigInst = PdfSignatureEngine.getInstance();
    // initialize engine with path of signed pdf (to be verified)
    sigInst.initVerify(fileToBeVerified, null);

    // this is a very rudimental signature verification, that only checks each
    // signature value
    sigInst.verify();

    // use methods provided by CMSSignatureValidator class for a more detailed
    // verification
    PdfSignatureDetails[] signatures = sigInst.getSignatures();
    for (int i = 0; i < signatures.length; i++) {
      PdfSignatureDetails sig = signatures[i];

      // test signature details if signature is an approval signature (or a
      // certification signature)
      if (sig instanceof ApprovalSignature) {
        ApprovalSignature sigApp = (ApprovalSignature) sig;
        System.out.println("signature " + (i + 1) + " of " + signatures.length
            + " signed by: " + sigApp.getSignerCertificate().getSubjectDN().toString());
        sigApp.verifySignatureValue();
        System.out.println("signature valid.");

        // check validity of certificate at signing time
        X509Certificate certificate = sigApp.getSignerCertificate();
        Calendar signatureDate = sigApp.getSigningTime();
        certificate.checkValidity(signatureDate.getTime());
        System.out.println("certificate valid at signing time.");

        if (sigApp.getSignatureTimeStampToken() != null) {
          sigApp.verifySignatureTimestampImprint();
          System.out.println("timestamp signature valid.");
        }

        RevocationInfoArchival revocationInfo = sigApp.getRevocationInformation();
        if (revocationInfo != null) {
          CertStatus certStatus = sigApp.getOcspRevocationStatus();
          if (certStatus != null && certStatus.getCertStatus() != CertStatus.GOOD
              || sigApp.getCrlRevocationStatus())
            System.out.println("signer certificate has been revoked");
          else
            System.out.println("signer certificate valid (not revoked)");
        }
      }
    }
    sigInst.closeDocument();
  }

  /**
   * Start demo, choose key and certificate from PKCS#11 token, create the signed PDF and verify the
   * signed PDF.
   * 
   * @param filePath
   *          path to the PKCS#12 file
   * @param password
   *          password of the PKCS#12 file
   * @throws GeneralSecurityException
   *           if key can't be retrieved or signer certificate already expired
   * @throws IOException
   *           if any files can't be read or written
   * @throws PdfSignatureException
   *           if errors occur during signing or verification
   * @throws CmsCadesException
   *           if the signature is invalid or certificates are revoked or missing
   * @throws TspVerificationException
   *           if timestamp is invalid
   */
  private void start() throws GeneralSecurityException, IOException,
      PdfSignatureException, CmsCadesException, TspVerificationException {

    String fileToBeSigned = "test.pdf";
    String newSignedFile = "test-signed-pkcs11.pdf";

    getKeyAndCerts();
    signPdf(fileToBeSigned, newSignedFile);
    System.out.println("File has been signed successfully!");
    verifySignedPdf(newSignedFile);
    System.out.println("Signature is valid!");

  }

  /**
   * Runs the demo. If no arguments are given, PKCS#11 module is read from the static properties
   * file. Otherwise the expected argument is one string containing the module's name.
   * 
   * @param args
   *          the name (and path) of the PKCS#11 module or empty
   * @throws Exception
   *           if errors occur during signature creation or verification
   */
  public static void main(String[] args) throws Exception {
    PdfSignatureDemoPkcs11 demo;
    if (args.length > 0) {
      demo = new PdfSignatureDemoPkcs11(args[0]);
    } else {
      demo = new PdfSignatureDemoPkcs11();
    }
    demo.start();
  }

}
