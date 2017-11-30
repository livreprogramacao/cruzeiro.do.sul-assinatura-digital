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
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.pdf.cmscades.OcspResponseUtil;
import iaik.pdf.cmscades.TimeStampTokenUtil;
import iaik.pdf.parameters.CertificateValidationData;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.pdf.parameters.PadesLTVParameters;
import iaik.pdf.signature.ApprovalSignature;
import iaik.pdf.signature.DocumentTimestamp;
import iaik.pdf.signature.PdfSignatureDetails;
import iaik.pdf.signature.PdfSignatureEngine;
import iaik.pdf.signature.PdfSignatureException;
import iaik.pdf.signature.PdfSignatureInstance;
import iaik.security.provider.IAIK;
import iaik.tsp.TimeStampToken;
import iaik.tsp.TspVerificationException;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.CertStatus;
import iaik.x509.ocsp.OCSPResponse;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

/**
 * This demo shows how to create signatures according to PAdES-LTV (PAdES Long Term Validation).
 * Adds validation data to the PDF document that can later be used for the verification of
 * signatures and certificates included in the document. Signatures can then be verified even if
 * external sources may no longer be available.
 */
public class PadesLtvDemo {

  static String fileToBeSigned = "test.pdf";
  static String newSignedFile = "test_signed.pdf";
  static String signedFileLtv = "test_signed_ltv.pdf";

  private PrivateKey privKey_;
  private Certificate[] certChain_;
  private PdfSignatureInstance signatureInstance_;

  /**
   * Adds the required IAIK JCE provider. Instantiates the signature instance used throughout this
   * demo.
   */
  public PadesLtvDemo() {
    Security.addProvider(new IAIK());
    signatureInstance_ = PdfSignatureEngine.getInstance();
  }

  /**
   * Read key and certificate chain from PKCS#12 file.
   * 
   * @param filePath
   *          path to PKCS#12 file
   * @param pw
   *          password for PKCS#12 file
   * @throws GeneralSecurityException
   *           if key can't be retrieved
   * @throws IOException
   *           if file can't be read
   */
  private void getKeyAndCerts(String filePath, String pw)
      throws GeneralSecurityException, IOException {
    System.out
        .println("reading signature key and certificates from file " + filePath + ".");

    FileInputStream fis = new FileInputStream(filePath);
    KeyStore store = KeyStore.getInstance("PKCS12", "IAIK");
    store.load(fis, pw.toCharArray());

    Enumeration<String> aliases = store.aliases();
    String alias = (String) aliases.nextElement();
    privKey_ = (PrivateKey) store.getKey(alias, pw.toCharArray());
    certChain_ = store.getCertificateChain(alias);
    fis.close();
  }

  /**
   * 
   * Configure signature engine to create a signed PDF document.
   * 
   * @param fileToBeSigned
   *          filename of PDF document to be signed
   * @param signedFilePath
   *          filename of the new signed PDF
   * @throws IOException
   *           if I/O errors occur
   * @throws PdfSignatureException
   *           if some parameters are invalid or errors occur during signing
   */
  private void signPdf(String fileToBeSigned, String signedFilePath)
      throws IOException, PdfSignatureException {
    System.out.println("\n#### signing the file " + fileToBeSigned
        + " and saving signed file to " + signedFilePath + ". #### \n");

    // set parameters for subfilter adbe.pkcs7.detached, use detached false for
    // subfilter adbe.pkcs7.sha1
    // PadesBasicParameters params = new PadesBasicParameters(true);
    // set parameters for subfilter ETSI.CAdES.detached
    PadesBESParameters params = new PadesBESParameters();

    params.setDigestAlgorithm("SHA512");
    params.setSignatureReason("test");
    params.setSignatureLocation("Graz");
    params.setSignatureContactInfo("Max");

    // set timestamp authority to add timestamp as unsigned attribute in
    // signature
    String tsaUrl = null;
    for (int i = 0; i < certChain_.length; i++) {
      X509Certificate cert = (X509Certificate) certChain_[i];
      try {
        tsaUrl = TimeStampTokenUtil.getTsaUrl(cert);
      } catch (GeneralSecurityException e) {
        // ignore - use default tsa url
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

    // initialize engine with path to original pdf (to be signed), private key
    // for signature creation,
    // certificates and parameters
    signatureInstance_.initSign(fileToBeSigned, null, signedFilePath, privKey_,
        certChain_, params);

    System.out.println("signing to file " + signedFilePath + " ...");
    // create signed pdf using specified name
    signatureInstance_.sign();
  }

  /**
   * Extracts and retrieves some exemplary validation data used for signature creation and adds this
   * data to the document, protecting it with a document timestamp.
   * 
   * @param fileToBeVerified
   *          the signed document
   * @param fileWithLtvData
   *          file path to use for saving the document containing ltv data and document timestamp
   * @param tsaUrl
   *          URL of the timestamp authority
   * @param username
   *          username for authorization
   * @param password
   *          password for authorization
   * @throws PdfSignatureException
   *           if errors occur during signature verification or when adding ltv data and document
   *           timestamp
   * @throws CmsCadesException
   *           if revocation info can't be retrieved
   * @throws TspVerificationException
   *           if an error occurs when requesting and verifying the timestamp
   * @throws IOException
   *           in case of I/O errors
   */
  private void verifyAndAddLtvData(String fileToBeVerified, String fileWithLtvData,
      String tsaUrl, String tsaUsername, String tsaPw) throws PdfSignatureException,
          CmsCadesException, TspVerificationException, IOException {
    // initialize engine with path of signed pdf (to be verified)
    signatureInstance_.initVerify(fileToBeVerified, null);
    System.out.println(
        "\n#### verifying file " + fileToBeVerified + " and adding LTV data ... ####\n");

    // this is a very rudimental signature verification, that only checks each
    // signature value
    signatureInstance_.verify();

    // archive all information used for signature and certificate verification
    PadesLTVParameters ltvInfos = new PadesLTVParameters();

    PdfSignatureDetails[] signatures = signatureInstance_.getSignatures();
    for (int i = 0; i < signatures.length; i++) {
      PdfSignatureDetails sig = signatures[i];

      // check if it's a normal signature or a document timestamp
      if (sig instanceof ApprovalSignature) {
        ApprovalSignature signature = (ApprovalSignature) sig;
        CadesSignature cadesSig = signature.getCMSSignature();
        X509Certificate[] certChain = signature.getCertificateChain(null);
        TimeStampToken tst = cadesSig.getSignatureTimeStampToken(0);
        if (tst != null) {
          Certificate[] tsaCertChain = tst.getCertificates();
          // add tsa cert chain - ideally togehter with revocation information
          ltvInfos.addGlobalValidationData(tsaCertChain, null, null);
        }

        // add revocation information
        OCSPResponse[] responses = null;
        if (certChain.length > 2) {
          String ocspUrl = null;
          try {
            ocspUrl = OcspResponseUtil.getOcspUrl(certChain[0]);
          } catch (GeneralSecurityException e) {
            // ignore - do not add OCSP response
          }
          if (ocspUrl != null) {
            OCSPResponse resp = OcspResponseUtil.createOcspResponse(certChain[0],
                certChain[1], ocspUrl);
            responses = new OCSPResponse[] { resp };
          }
        }
        X509CRL[] crls = null;
        if (responses == null) {
          // try crl
          X509CRL crl = CadesSignature.getCRL(certChain[0]);
          if (crl != null) {
            crls = new X509CRL[] { crl };
          }
        }

        // add signature cert chain and revocation infos
        ltvInfos.addGlobalValidationData(certChain, crls, responses);

        // add these infos also together with corresponding signature
        ltvInfos.addValidationData(((ApprovalSignature) sig).getEncodedCmsSignature(),
            certChain, crls, responses);
        if (tst != null) {
          ltvInfos.addValidationData(tst, tst.getCertificates(), null, null);
        }
      }
    }
    signatureInstance_.addArchivalTimestamp(tsaUrl, tsaUsername, tsaPw, ltvInfos,
        fileWithLtvData);
  }

  /**
   * Verify document timestamp to ensure, that the content has not been changed. Extract some
   * included ltv data (revocation information) and use it to ensure that the signer certificate has
   * not been revoked.
   * 
   * @param ltvDocument
   *          document containing ltv data protected by a document timestamp
   * @throws PdfSignatureException
   *           if errors occur during ltv data extraction or timestamp verification
   * @throws CmsCadesException
   *           if signature or OCSP responses are invalid or can't be verified
   * @throws TspVerificationException
   *           if the timestamp signature is invalid or can't be parsed
   * @throws IOException
   *           if timestamp or ltv data can't be read
   */
  private void readLtvData(String ltvDocument) throws PdfSignatureException,
      CmsCadesException, CMSSignatureException, TspVerificationException, IOException {
    signatureInstance_.initVerify(ltvDocument, null);

    System.out.println("\n#### read ltv data from " + ltvDocument
        + " and use them for verification ... ####\n");

    // verify signatures enveloped by a document timestamp
    PdfSignatureDetails[] signatures = signatureInstance_.getSignatures();
    ArrayList<PdfSignatureDetails> signaturesForValidation = new ArrayList<PdfSignatureDetails>();
    for (int i = 0; i < signatures.length; i++) {
      PdfSignatureDetails sig = signatures[i];
      if (sig instanceof DocumentTimestamp) {
        DocumentTimestamp docTst = (DocumentTimestamp) sig;

        // verify that timestamped data has not been changed
        docTst.verifyDocumentTimestamp();

        PadesLTVParameters ltvInfos = docTst.getLTVParams();
        for (PdfSignatureDetails signature : signaturesForValidation) {
          // partly verify the signature with these infos (complete verification
          // is not handled here)
          CertificateValidationData globalValidationData = ltvInfos
              .getGlobalValidationData();
          CertificateValidationData assignedValidationData;
          java.security.cert.X509Certificate signerCert;
          if (signature instanceof ApprovalSignature) {
            ApprovalSignature curSignature = (ApprovalSignature) signature;
            assignedValidationData = ltvInfos
                .getValidationData(curSignature.getEncodedCmsSignature());
            System.out.println("Found validation data assigned to this signature.");
            signerCert = curSignature.verifySignatureValue();
          } else if (signature instanceof DocumentTimestamp) {
            DocumentTimestamp timestampSignature = (DocumentTimestamp) signature;
            TimeStampToken token = timestampSignature.getDocumentTimeStamp();
            assignedValidationData = ltvInfos.getValidationData(token);
            signerCert = token.getSigningCertificate();
          } else {
            // will not occur
            throw new PdfSignatureException("unknown signature type.");
          }
          for (X509CRL crl : globalValidationData.getCrls()) {
            if (crl.isRevoked(signerCert)) {
              throw new PdfSignatureException("signer certificate is revoked.");
            }
          }

          for (X509CRL crl : assignedValidationData.getCrls()) {
            if (crl.isRevoked(signerCert)) {
              throw new PdfSignatureException("signer certificate is revoked.");
            }
          }

          for (OCSPResponse resp : globalValidationData.getOcspResponses()) {
            CertStatus certStatus = OcspResponseUtil.getOCSPResponseCertStatus(resp,
                signerCert, null, null);
            if (certStatus.getCertStatus() != CertStatus.GOOD)
              throw new CmsCadesException("signer certificate revoked");
          }

          for (OCSPResponse resp : assignedValidationData.getOcspResponses()) {
            CertStatus certStatus = OcspResponseUtil.getOCSPResponseCertStatus(resp,
                signerCert, null, null);
            if (certStatus.getCertStatus() != CertStatus.GOOD)
              throw new CmsCadesException("signer certificate revoked");
          }
          System.out.println("Signer certificate not revoked.");
        }
        signaturesForValidation.clear();
      }
      signaturesForValidation.add(sig);
    }
  }

  /**
   * Shows how to add and read ltv data protected by a document timestamp.
   * 
   * @param filePath
   *          path to the PKCS#12 file
   * @param password
   *          password of the PKCS#12 file
   * @throws PdfSignatureException
   *           if errors occur during signature creation and verification
   * @throws CmsCadesException
   *           if the cms signature or the ocsp response is invalid or can't be verified
   * @throws TspVerificationException
   *           if the timestamp is invalid or can't be verified
   * @throws GeneralSecurityException
   *           if the signing key can't be read or OCSP request can't be sent
   * @throws IOException
   *           if I/O errors occur
   */
  private void start(String filePath, String password) throws PdfSignatureException,
      CmsCadesException, TspVerificationException, GeneralSecurityException, IOException {
    getKeyAndCerts(filePath, password);
    signPdf(fileToBeSigned, newSignedFile);
    verifyAndAddLtvData(newSignedFile, signedFileLtv,
        "http://tsp.iaik.tugraz.at/tsp/TspRequest", null, null);
    readLtvData(signedFileLtv);
    signatureInstance_.closeDocument();
  }

  /**
   * Runs the demo. Expected arguments are a PKCS#12 file and the corresponding password.
   * 
   * @param args
   *          file and password containing the private key for creating the signatures
   * @throws Exception
   *           if errors occur during signature creation or verification
   */
  public static void main(String[] args) throws Exception {

    if (args == null || args.length < 2)
      printUsage();
    else {
      PadesLtvDemo demo = new PadesLtvDemo();
      demo.start(args[0], args[1]);
    }
  }

  public static void printUsage() {
    System.out.println("Usage: PadesLtvDemo <PKCS#12 file> <password for PKCS#12 file>");
    System.out.println(" e.g.: PadesLtvDemo mykeys.p12 password");
  }

}
