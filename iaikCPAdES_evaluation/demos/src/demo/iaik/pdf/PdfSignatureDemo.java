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

//import iaik.cms.SecurityProvider;
//import iaik.cms.ecc.ECCelerateProvider;
import iaik.cms.CMSSignatureException;
import iaik.pdf.asn1objects.RevocationInfoArchival;
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.pdf.cmscades.OcspResponseUtil;
import iaik.pdf.cmscades.TimeStampTokenUtil;
import iaik.pdf.parameters.LegalContentAttestation;
import iaik.pdf.parameters.LegalContentAttestation.ContentType;
import iaik.pdf.parameters.PadesBESParameters;
import iaik.pdf.parameters.PadesBasicParameters;
import iaik.pdf.signature.ApprovalSignature;
import iaik.pdf.signature.CertificationSignature;
import iaik.pdf.signature.CertificationSignature.ModificationPermission;
import iaik.pdf.signature.PdfSignatureDetails;
import iaik.pdf.signature.PdfSignatureEngine;
import iaik.pdf.signature.PdfSignatureException;
import iaik.pdf.signature.PdfSignatureInstance;
//import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIK;
import iaik.tsp.TspVerificationException;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.CertStatus;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Enumeration;

/**
 * This demo shows how to use the PdfSignatureEngine. This engine should allow easy and flexible
 * specification of all kinds of parameters.
 */
public class PdfSignatureDemo {

  static String fileToBeSigned = "test.pdf";
  static String newSignedFile = "test_signed.pdf";
  static String newCertifiedFile = "test_certified.pdf";
  static String newCertifiedSignedFile = "test_certified_signed.pdf";

  private PrivateKey privKey_;
  private Certificate[] certChain_;
  private PdfSignatureInstance signatureInstance_;

  public PdfSignatureDemo() {
    Security.addProvider(new IAIK());
    signatureInstance_ = PdfSignatureEngine.getInstance();
    // you can add the ECCelerate provider, if you use EC keys
    // Security.addProvider(new ECCelerate());
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
   * Sign the given file using the previously set key.
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
    System.out.println("\n#### signing the file " + fileToBeSigned
        + " and saving signed file to " + signedFilePath + ". #### \n");

    prepareSigning(fileToBeSigned, signedFilePath);

    System.out.println("signing to file " + signedFilePath + " ...");
    // create signed pdf using specified name
    signatureInstance_.sign();
  }

  /**
   * Certify the given PDF. A standard signature is added together with some settings, defining what
   * kind of modifications are allowed without invalidating the signature.
   * 
   * @param fileToBeSigned
   *          filename of PDF document to be signed
   * @param certifiedFilePath
   *          filename of the new certified PDF
   * @param permissions
   *          settings defining allowed modifications
   * @throws IOException
   *           if a file can't be read or written
   * @throws PdfSignatureException
   *           if errors during signing occur
   */
  private void certifyPdf(String fileToBeCertified, String certifiedFilePath,
      ModificationPermission permissions) throws IOException, PdfSignatureException {
    System.out.println("\n#### Certifying the file " + fileToBeCertified
        + " and saving certified file to " + certifiedFilePath + ". ####\n");

    prepareSigning(fileToBeCertified, certifiedFilePath);

    System.out.println("Defining Legal Content Attestation.");
    LegalContentAttestation lca = new LegalContentAttestation();
    lca.addEntry(ContentType.javaScriptActions, 2);
    lca.setAttestationString(
        "I hereby confirm, that I have read and understood this agreement.");

    System.out.println("certifying to file " + certifiedFilePath + ".");
    System.out.println(
        "Further signatures are allowed, other changes shall be prevented by PDF editors.");
    // create signed pdf using specified name
    signatureInstance_.certify(permissions, lca);
  }

  /**
   * Prepare the signature parameters and initialize signature instance.
   * 
   * @param fileToBeSigned
   *          filename of PDF document to be signed
   * @param signedFilePath
   *          filename of the new signed PDF
   * @throws IOException
   *           if document can't be read or written
   * @throws PdfSignatureException
   *           if parameters are invalid or certificates can't be parsed
   */
  private void prepareSigning(String fileToBeSigned, String signedFilePath)
      throws IOException, PdfSignatureException {

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
    } catch (IOException e) {
      // only set crl if it can be extracted
    } catch (CmsCadesException e) {
      // only set crl if it can be extracted
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

    // set the appropriate security provider, if you use EC keys
    // SecurityProvider.setSecurityProvider(new ECCelerateProvider());

    // initialize engine with path to original pdf (to be signed), private key
    // for signature creation,
    // certificates and parameters
    signatureInstance_.initSign(fileToBeSigned, null, signedFilePath, privKey_,
        certChain_, params);
  }

  /**
   * Verify given signed PDF document.
   * 
   * @param fileToBeVerified
   *          the signed or certified PDF document.
   * @throws IOException
   *           if the signed document can't be read
   * @throws PdfSignatureException
   *           if errors during verification occur
   * @throws CmsCadesException
   *           if the signature is invalid or certificates are revoked or missing
   * @throws TspVerificationException
   *           if timestamp is invalid
   * @throws CertificateException
   *           if certificate already expired
   */
  private void verifySignedPdf(String fileToBeVerified)
      throws IOException, PdfSignatureException, CmsCadesException, CMSSignatureException,
      TspVerificationException, CertificateException {

    // initialize engine with path of signed pdf (to be verified)
    signatureInstance_.initVerify(fileToBeVerified, null);

    System.out.println("\n#### verifying file " + fileToBeVerified + " ... ####\n");

    // this is a very rudimental signature verification, that only checks each
    // signature value
    signatureInstance_.verify();

    // use methods provided by CMSSignatureValidator class for a more detailed
    // verification
    PdfSignatureDetails[] signatures = signatureInstance_.getSignatures();
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

      // if PDF has been certified, you can also get some more infos
      if (sig instanceof CertificationSignature) {
        getCertificationInfos((CertificationSignature) sig, signatures, fileToBeVerified);
      }

      if (sig.isModified()) {
        System.out.println("signature " + sig.getName() + " has been modified.");
      }
    }

  }

  /**
   * Extract details about the certification signature (legal content attestation, allowed
   * modifications).
   * 
   * @param sig
   *          the certification signature
   * @param signatures
   *          all standard signatures contained in the document
   * @param fileToBeVerified
   *          the document containing the signatures to be verified
   * @throws PdfSignatureException
   *           if more than 1 certification signature is contained or actual modifications do not
   *           correspond with settings
   * @throws IOException
   *           if the document can't be read
   */
  private void getCertificationInfos(CertificationSignature sig,
      PdfSignatureDetails[] signatures, String fileToBeVerified)
          throws PdfSignatureException, IOException {
    System.out.println("\n#### File contains a certification signature. ####\n");

    LegalContentAttestation lca = sig.getLegalContentAttestation();
    if (lca != null) {
      System.out
          .println("Certification signature contains the following attestation string: "
              + lca.getAttestationString());
    }

    StringWriter modRevisions = new StringWriter();
    int i = 1;
    String separator = "";
    for (PdfSignatureDetails sigCur : signatures) {
      if (sigCur.isModified()) {
        // the original version of a revision - if you want to compare them
        sigCur.getRevision(fileToBeVerified + "_rev" + i);

        modRevisions.write(separator);
        modRevisions.write(Integer.toString(i));
        separator = ", ";
      }
      i++;
    }
    modRevisions.flush();
    String modRevisionsString = modRevisions.toString();
    if (modRevisionsString.length() != 0)
      System.out.println("There have been changes after the following revisions: "
          + modRevisions.toString());
    else
      System.out
          .println("Document has not been changed, after the signature was applied.");

    ModificationPermission perms = sig.getModificationPermission();
    if (perms != null) {
      System.out.println("Certification signature permits the following changes:");
      switch (perms) {
      case NoModifications:
        System.out.println("No modification are allowed.");
        if (modRevisionsString.length() != 0)
          throw new PdfSignatureException(
              "Document has been modified, although no modifications allowed.");
        break;
      case SignaturesFormsTemplates:
        System.out.println(
            "Filling in forms, instantiating page templates and signing is allowed.");
        break;
      case AnnotationsSignaturesFormsTemplates:
        System.out.println(
            "Filling in forms, instantiating page templates, signing and creation, deletion, and modification of annotations is allowed.");
        break;
      }
    }
  }

  /**
   * Start demo, read key and certificates from file, create a signed and certified PDF and verify
   * the PDF.
   * 
   * @param filePath
   *          path to the PKCS#12 file
   * @param password
   *          password of the PKCS#12 file
   * @throws GeneralSecurityException
   *           if key can't be retrieved or the signer certificate has expired
   * @throws IOException
   *           if I/O errors occur
   * @throws PdfSignatureException
   *           if errors occur during signature creation and verification
   * @throws CmsCadesException
   *           if signature is invalid or certificates are revoked or missing
   * @throws TspVerificationException
   *           if the timestamp is invalid
   */
  private void start(String filePath, String password) throws GeneralSecurityException,
      IOException, PdfSignatureException, CmsCadesException, TspVerificationException {

    getKeyAndCerts(filePath, password);

    // certify a PDF (allow signatures and forms)
    certifyPdf(fileToBeSigned, newCertifiedFile,
        ModificationPermission.SignaturesFormsTemplates);
    System.out.println("File has been certified successfully!");

    // verify the certified PDF
    verifySignedPdf(newCertifiedFile);

    // sign the PDF and verify
    signPdf(fileToBeSigned, newSignedFile);
    System.out.println("File has been signed successfully!");
    verifySignedPdf(newSignedFile);

    // sign the certified PDF
    signPdf(newCertifiedFile, newCertifiedSignedFile);
    System.out.println("File has been signed successfully!");

    // verify the signed and certified PDF
    verifySignedPdf(newCertifiedSignedFile);

    // certify a PDF and do not allow modifications (even no signatures)
    certifyPdf(fileToBeSigned, newCertifiedFile, ModificationPermission.NoModifications);
    System.out.println("File has been certified successfully!");

    // sign the certified PDF
    signPdf(newCertifiedFile, newCertifiedSignedFile);
    System.out.println("File has been signed successfully!");

    try {
      // verify the signed and certified PDF - if you check modification
      // permissions and actual modifications
      // you can see that this is not allowed and you can react (e.g. with an
      // exception)
      verifySignedPdf(newCertifiedSignedFile);
    } finally {
      System.out.println("\nAn exception should now occur:");
      // finally close documents that may still be open
      signatureInstance_.closeDocument();
    }

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
      PdfSignatureDemo demo = new PdfSignatureDemo();
      demo.start(args[0], args[1]);
    }
  }

  public static void printUsage() {
    System.out
        .println("Usage: PdfSignatureDemo <PKCS#12 file> <password for PKCS#12 file>");
    System.out.println(" e.g.: PdfSignatureDemo mykeys.p12 password");
  }

}
