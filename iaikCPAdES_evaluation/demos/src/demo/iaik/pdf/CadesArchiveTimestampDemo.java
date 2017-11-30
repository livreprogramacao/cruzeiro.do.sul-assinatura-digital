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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Random;

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.AttributeValue;
import iaik.asn1.structures.Name;
import iaik.cms.SignedData;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.pdf.asn1objects.ArchiveTimeStampv3;
import iaik.pdf.asn1objects.AtsHashIndex;
import iaik.pdf.asn1objects.AbstractAtsHashIndex;
import iaik.pdf.asn1objects.AtsHashIndexv3;
import iaik.pdf.asn1objects.SignatureTimeStamp;
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.pdf.cmscades.OcspResponseUtil;
import iaik.pdf.parameters.CadesLTAParameters;
import iaik.pdf.parameters.CadesTParameters;
import iaik.security.provider.IAIK;
import iaik.smime.attributes.SignatureTimeStampToken;
import iaik.tsp.TimeStampToken;
import iaik.utils.Util;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.BasicOCSPResponse;
import iaik.x509.ocsp.CertID;
import iaik.x509.ocsp.CertStatus;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.SingleResponse;

/**
 * This demo shows how to add and verify an archive timestamp and extract the archived data for
 * signature verification.
 */
public class CadesArchiveTimestampDemo {

  private PrivateKey privKey_;
  private X509Certificate[] certChain_;
  private X509Certificate signerCert_;
  private byte[] randomData_;

  public CadesArchiveTimestampDemo() {
    Security.addProvider(new IAIK());
  }

  /**
   * Verifies the signature rudimentary and prepares the archive timestamp parameters by adding all
   * certificates, CRLs and OCSP responses that had been used for the verification.
   * 
   * @param cadesSig
   *          the signature to be verified and archived
   * @return the parameters needed for adding the archive timestamp
   * @throws Exception
   *           if the signature can't be read or is not valid, or if the revocation information
   *           can't be retrieved
   */
  private CadesLTAParameters verifySignatureAndPrepareDataToArchive(
      CadesSignatureStream cadesSig) throws Exception {
    CadesLTAParameters params = new CadesLTAParameters(
        "http://tsp.iaik.tugraz.at/tsp/TspRequest", null, null, null);

    // verify the signature and add all required data to the Cades-A parameters
    // this is only an exemplary verification
    ArrayList<OCSPResponse> ocspResponses = new ArrayList<OCSPResponse>();
    ArrayList<X509CRL> crls = new ArrayList<X509CRL>();

    cadesSig.verifySignatureValue(signerCert_);
    String ocspUrl = OcspResponseUtil.getOcspUrl(signerCert_);
    if (ocspUrl != null && certChain_.length > 1) {
      ocspResponses
          .add(OcspResponseUtil.createOcspResponse(signerCert_, certChain_[1], ocspUrl));
    } else { // try crl
      X509CRL crl = CadesSignature.getCRL(signerCert_);
      if (crl != null)
        crls.add(crl);
    }

    SignatureTimeStamp[] sigTsps = cadesSig.getSignatureTimeStamps(signerCert_);
    for (SignatureTimeStamp tsp : sigTsps) {
      tsp.verifyTimeStampToken(null);
      TimeStampToken tspToken = tsp.getTimeStampToken();
      X509Certificate tsaCert = Util.convertCertificate(tspToken.getSigningCertificate());
      Certificate[] certs = tspToken.getCertificates();
      X509Certificate[] certChain = Util.createCertificateChain(tsaCert, certs);
      ocspUrl = OcspResponseUtil.getOcspUrl(tsaCert);
      if (ocspUrl != null && certChain.length > 1) {
        ocspResponses
            .add(OcspResponseUtil.createOcspResponse(tsaCert, certChain[1], ocspUrl));
      } else { // try crl
        X509CRL crl = CadesSignature.getCRL(tsaCert);
        if (crl != null)
          crls.add(crl);
      }
    }

    params.addArchiveDetails(null, null, ocspResponses.toArray(new OCSPResponse[0]));

    return params;
  }

  /**
   * Adds an archive timestamp to the given signature using the given parameters.
   * 
   * @param cadesSig
   *          the signature to be archived
   * @param params
   *          the archive parameters to be used
   * @throws Exception
   *           if the signature can't be read, the parameter's data can't be added or the timestamp
   *           can't be created
   */
  private void addArchiveTimestamp(CadesSignatureStream cadesSig,
      CadesLTAParameters params) throws Exception {
    cadesSig.addArchiveTimeStamp(signerCert_, params);
    cadesSig.encodeUpgradedSignature();
  }

  /**
   * Verifies the archive timestamp, extracts the archived verification data and uses this data to
   * verify the signature.
   * 
   * @param archivedSignature
   *          the archived signature
   * @param data
   *          the data signed by the given signature
   * @throws Exception
   *           if the signature can't be read or verified
   */
  private void extractTimestampAndData(InputStream archivedSignature, InputStream data)
      throws Exception {
    CadesSignatureStream cadesSig = new CadesSignatureStream(archivedSignature, data);
    SignedDataStream signedData = cadesSig.getSignedDataObject();
    SignerInfo[] signerInfos = signedData.getSignerInfos();
    for (int i = 0; i < signerInfos.length; i++) {
      X509Certificate signerCert = signedData.verify(i);
      System.out.println("Signature value verified successfully.");

      ArchiveTimeStampv3[] archiveTsps = cadesSig.getArchiveTimeStamps(signerCert);
      for (ArchiveTimeStampv3 tsp : archiveTsps) {
        tsp.verifyTimeStampToken(null);
        System.out.println("Archive time-stamp signature verified successfully.");
        AbstractAtsHashIndex dataReferences = tsp.getAtsHashIndex();
        // ETSI EN 319 122-1 defines the ats-hash-index attribute to be invalid if it includes
        // references that do not match objects in the archived signature
        if (dataReferences instanceof AtsHashIndexv3)
          if (dataReferences.containsReferencesWithoutOriginalValues(cadesSig,
              signerInfos[i]))
            System.out.println(
                "!! Archive time-stamp invalid: ATSHashIndexv3 contains references without matching data !!");

        // retrieved the archived data that can be used for verification

        Certificate[] certs = dataReferences.getIndexedCertificates(cadesSig);
        BasicOCSPResponse[] ocspResponses = dataReferences
            .getIndexedOcspResponses(cadesSig);
        HashMap<ReqCert, BasicOCSPResponse> ocspResponsesMap = new HashMap<ReqCert, BasicOCSPResponse>();
        for (BasicOCSPResponse resp : ocspResponses) {
          SingleResponse[] singleResponses = resp.getSingleResponses();
          for (SingleResponse singleResp : singleResponses) {
            ocspResponsesMap.put(singleResp.getReqCert(), resp);
          }
        }
        X509CRL[] crls = dataReferences.getIndexedCrls(cadesSig);

        // verify archived signature - only exemplary verification

        X509Certificate[] signerCertChain = Util.createCertificateChain(signerCert,
            certs);

        if (signerCertChain.length > 1) {
          CertID certID = new CertID(AlgorithmID.sha1,
              (Name) signerCertChain[1].getSubjectDN(), signerCertChain[1].getPublicKey(),
              signerCert.getSerialNumber());
          ReqCert reqCert = new ReqCert(ReqCert.certID, certID);
          BasicOCSPResponse resp = ocspResponsesMap.get(reqCert);
          if (resp != null) {
            resp.verify(signerCertChain[1].getPublicKey());
            CertStatus stat = resp.getSingleResponse(reqCert).getCertStatus();
            if (stat.getCertStatus() != CertStatus.GOOD)
              throw new CmsCadesException(
                  "Signer certificate status for signer info " + i + " not good.");
            System.out
                .println("Signer certificate status 'good' in archived OCSP response.");
          }
        }

        if (crls.length > 0) {
          for (X509CRL crl : crls) {
            if (crl.containsCertificate(signerCert) != null)
              throw new CmsCadesException("Signer certificate of signer info " + i
                  + " on crl and therefore revoked.");
          }
          System.out
              .println("Signer certificate not found on an archived revocation list.");
        }

        // handle archived unsigned attributes, e.g. check signature timestamps
        ArrayList<SignatureTimeStamp> sigTsps = new ArrayList<SignatureTimeStamp>();
        if (dataReferences instanceof AtsHashIndex) {
          Attribute[] attributes = ((AtsHashIndex) dataReferences)
              .getIndexedUnsignedAttributes(signerInfos[i]);
          for (Attribute attr : attributes) {
            if (attr.getType().equals(SignatureTimeStamp.oid)) {
              SignatureTimeStampToken stsp = (SignatureTimeStampToken) attr
                  .getAttributeValue();
              sigTsps
                  .add(new SignatureTimeStamp(stsp, signerInfos[i].getSignatureValue()));
            }
          }
        } else if (dataReferences instanceof AtsHashIndexv3) {
          AttributeValue[] attributeValues = ((AtsHashIndexv3) dataReferences)
              .getIndexedUnsignedAttrValues(signerInfos[i]);
          for (AttributeValue attr : attributeValues) {
            if (attr.getAttributeType().equals(SignatureTimeStamp.oid)) {
              sigTsps.add(
                  new SignatureTimeStamp(new SignatureTimeStampToken(attr.toASN1Object()),
                      signerInfos[i].getSignatureValue()));
            }
          }
        }
        for (SignatureTimeStamp sigTsp : sigTsps) {
          sigTsp.verifyTimeStampToken(null);
          System.out.println("Archived signature timestamp valid. Signature time: "
              + sigTsp.getTimeStampToken().getTSTInfo().getGenTime());
        }
      }
    }
  }

  /**
   * Signs data given as stream. By using parameters of type CadesBESParameters a CAdES signature
   * according to CAdES-BES will be created. For a CAdES-T signature use a CadesTParameters
   * instance.
   * 
   * @param data
   *          data stream to be signed
   * @param signatureStream
   *          output stream to write the signature to
   * @throws CmsCadesException
   *           if errors during signature creation occurred
   * @throws GeneralSecurityException
   *           if the specified digest algorithm is not available
   * @throws IOException
   *           if data can't be read
   */
  private void signDataStream(OutputStream signatureOutputStream, InputStream data)
      throws CmsCadesException, GeneralSecurityException, IOException {
    CadesSignatureStream cmsSig = new CadesSignatureStream(data, SignedData.EXPLICIT);
    CadesTParameters params = new CadesTParameters(
        "http://tsp.iaik.tugraz.at/tsp/TspRequest", null, null, null);
    cmsSig.addSignerInfo(privKey_, certChain_, params);
    cmsSig.encodeSignature(signatureOutputStream);
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
    certChain_ = Util.convertCertificateChain(store.getCertificateChain(alias));
    signerCert_ = certChain_[0];
    fis.close();
  }

  /**
   * Creates some random bytes to be signed.
   * 
   * @return the input stream reading the created random bytes
   */
  private InputStream getDataToBeSigned() {
    if (randomData_ == null) {
      Random random = new SecureRandom();
      randomData_ = new byte[1028];

      random.nextBytes(randomData_);
    }
    return new ByteArrayInputStream(randomData_);
  }

  /**
   * Provides an input stream to read the signature bytes from the given output stream.
   * 
   * @param os
   *          the output stream the signature has been written to
   * @return the InputStream to read the signature
   */
  private InputStream readSignature(ByteArrayOutputStream os) {
    try {
      ByteArrayInputStream signatureStream = new ByteArrayInputStream(os.toByteArray());
      return signatureStream;
    } finally {
      try {
        os.close();
      } catch (IOException e) {
      }
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
      ByteArrayOutputStream signatureStream;
      ByteArrayOutputStream archivedSignatureStream;

      CadesArchiveTimestampDemo demo = new CadesArchiveTimestampDemo();
      demo.getKeyAndCerts(args[0], args[1]);

      // sign some data
      System.out.println("\n### Sign some random data. ###");
      InputStream data = demo.getDataToBeSigned();
      signatureStream = new ByteArrayOutputStream();
      try {
        demo.signDataStream(signatureStream, data);
      } finally {
        data.close();
      }

      // read signature
      System.out.println("### Archive signature with archive timestamp. ###");
      data = demo.getDataToBeSigned();
      InputStream signature = demo.readSignature(signatureStream);
      archivedSignatureStream = new ByteArrayOutputStream();
      String archiveTimestampDigestAlgorithm = "SHA512";
      CadesSignatureStream cadesSig = new CadesSignatureStream(signature, data,
          new String[] { archiveTimestampDigestAlgorithm }, archivedSignatureStream);
      CadesLTAParameters params = demo.verifySignatureAndPrepareDataToArchive(cadesSig);
      // params.setUseAtsHashIndexv3(false);

      // add archive timestamp
      demo.addArchiveTimestamp(cadesSig, params);

      // check archive timestamp and get archived data
      System.out.println(
          "### Extract archived data and use it for signature verification. ###");
      signature = demo.readSignature(archivedSignatureStream);
      data = demo.getDataToBeSigned();
      demo.extractTimestampAndData(signature, data);

    }
  }

  public static void printUsage() {
    System.out.println(
        "Usage: CadesArchiveTimestampDemo <PKCS#12 file> <password for PKCS#12 file>");
    System.out.println(" e.g.: CadesArchiveTimestampDemo mykeys.p12 password");
  }

}
