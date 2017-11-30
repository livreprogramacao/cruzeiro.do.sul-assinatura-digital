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

import iaik.pdf.itext.OcspClientIAIK;
import iaik.pdf.itext.TSAClientIAIK;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.ProviderDigest;
import com.itextpdf.text.pdf.security.TSAClient;

/**
 * This demo uses a PKCS#11 token to calculate the signature value for the PDF signature. To do so,
 * the IAIK PKCS#11 provider is passed to the PrivateKeySignature instance.
 */
public class SignWithPKCS11Demo {

  /**
   * Specify properties for IAIK PKCS#11 provider and register IAIK JCE provider and PKCS#11
   * provider.
   * 
   * @param args
   *          optionally specify PKCS#11 module path
   */
  public static void main(String[] args) throws Exception {
    LoggerFactory.getInstance().setLogger(new SysoLogger());

    // for signing
    Security.addProvider(new IAIK());
    Properties properties = new Properties();
    // specify PKCS#11 module path if given
    if (args.length > 0)
      properties.put("PKCS11_NATIVE_MODULE", "pkcs11wrapper.dll");
    // you can use dynamic or static properties
    // properties.put("PKCS11_WRAPPER_PATH",
    // "/usr/iaik/lib/libpkcs11wrapper.so")
    // properties.put("SLOT_ID", "[1]");
    Provider iaikPkcs11Provider = new IAIKPkcs11(properties);
    Security.addProvider(iaikPkcs11Provider);

    // for verifying
    Security.addProvider(new BouncyCastleProvider());

    SignWithPKCS11Demo demo = new SignWithPKCS11Demo();
    demo.signWithPkcs11(iaikPkcs11Provider.getName());
    demo.verifyPdf("test-pkcs11signed.pdf");

    System.out.println("signing and verifying finished.");

  }

  /**
   * sign PDF document with PKCS#11 key
   * 
   * @param pkcs11ProviderName
   *          name of the PKCS#11 provider to be used
   * @throws Exception
   *           in case of any exceptions
   */
  public void signWithPkcs11(String pkcs11ProviderName) throws Exception {

    PrivateKey pk = null;
    Certificate[] chain = null;

    // find suitable key with PKCS#11 keystore
    KeyStore ks = KeyStore.getInstance("PKCS11KeyStore");
    ks.load(null, null);
    Enumeration<String> aliases = ks.aliases();
    while (aliases.hasMoreElements()) {
      String curAlias = aliases.nextElement();
      if (ks.isKeyEntry(curAlias) && ks.getCertificateChain(curAlias) != null
          && ks.getCertificateChain(curAlias).length > 0) {
        Key key = ks.getKey(curAlias, null);
        if (key instanceof PrivateKey) {
          pk = (PrivateKey) ks.getKey(curAlias, null);
          chain = ks.getCertificateChain(curAlias);
          break;
        }
      }
    }
    if (pk == null)
      throw new IOException("no suitable signature key found");

    // include OCSP response
    OcspClient ocspClient = new OcspClientIAIK();

    // extract URL to timestamp server from certificate
    TSAClient tsaClient = null;
    for (int i = 0; i < chain.length; i++) {
      X509Certificate cert = (X509Certificate) chain[i];
      String tsaUrl = CertificateUtil.getTSAURL(cert);
      if (tsaUrl != null) {
        tsaClient = new TSAClientIAIK(tsaUrl);
        break;
      }
    }
    // or use preferred timestamp server
    if (tsaClient == null) {
      String tsaUrl = "http://tsp.iaik.tugraz.at/tsp/TspRequest";
      tsaClient = new TSAClientIAIK(tsaUrl);
    }

    // include CRLs in signature - let iText extract the CRLs
    List<CrlClient> crlList = new ArrayList<CrlClient>();
    crlList.add(new CrlClientOnline(chain));

    // sign 'test.pdf', save signed PDF to 'test-pkcs11signed.pdf'
    SignWithPKCS11HSM app = new SignWithPKCS11HSM();
    app.sign("test.pdf", "test-pkcs11signed.pdf", chain, pk, DigestAlgorithms.SHA256,
        pkcs11ProviderName, "IAIK", CryptoStandard.CMS, "HSM test", "Graz", crlList,
        ocspClient, tsaClient, 0);

  }

  /**
   * Verifies all signatures in the given PDF.
   * 
   * @param path
   *          path to the PDF file, that shall be verified.
   * @return true, if signatures are valid, throws an exception otherwise
   * @throws Exception
   *           if signatures are not valid or in case of errors during validation
   */
  public boolean verifyPdf(String path) throws Exception {
    PdfReader reader = new PdfReader(path);
    AcroFields af = reader.getAcroFields();
    ArrayList<?> names = af.getSignatureNames();
    ArrayList<String> invalidSignatures = new ArrayList<String>();

    for (int k = 0; k < names.size(); ++k) {
      String name = (String) names.get(k);
      PdfPKCS7 pk = af.verifySignature(name);
      if (!pk.verify()) {
        invalidSignatures.add(name);
        continue;
      }

      Calendar cal = pk.getSignDate();
      Certificate pkc[] = pk.getCertificates();

      String fails = CertificateVerification.verifyCertificate((X509Certificate) pkc[0],
          pk.getCRLs(), cal);
      if (fails != null) {
        System.out.println("fails: " + fails);
        invalidSignatures.add(name);
        continue;
      }
      if (!pk.isRevocationValid()) {
        invalidSignatures.add(name);
      }
    }

    if (invalidSignatures.size() > 0) {
      String separator = "";
      StringBuffer namesString = new StringBuffer();
      for (String signatureName : invalidSignatures) {
        namesString.append(separator);
        namesString.append(signatureName);
        separator = ", ";
      }
      if (invalidSignatures.size() > 1) {
        throw new GeneralSecurityException(
            "the signatures " + namesString.toString() + " are invalid!");
      } else {
        throw new GeneralSecurityException(
            "the signature " + namesString.toString() + " is invalid!");
      }
    }
    return true;

  }

  /**
   * helper class carrying out actual signature process
   */
  private static class SignWithPKCS11HSM {

    /**
     * common signature method
     * 
     * @param src
     *          path to PDF document that shall be signed
     * @param dest
     *          filename for the new signed PDF document
     * @param chain
     *          certificate chain
     * @param pk
     *          private key used for signing
     * @param digestAlgorithm
     *          used digest algorithm
     * @param signatureProvider
     *          JCE provider to be used for signature calculation
     * @param mdProvider
     *          JCE provider to be used for message digest calculation
     * @param subfilter
     *          used subfilter (cms or cades)
     * @param reason
     *          reason for signing
     * @param location
     *          location of signing
     * @param crlList
     *          CRLs to be included
     * @param ocspClient
     *          OcspClient to be used to receive OCSP response
     * @param tsaClient
     *          TSAClient to create timestamp
     * @param estimatedSize
     *          estimated size of signature
     * @throws Exception
     *           in case of any problems
     */
    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
        String digestAlgorithm, String signatureProvider, String mdProvider,
        CryptoStandard subfilter, String reason, String location,
        Collection<CrlClient> crlList, OcspClient ocspClient, TSAClient tsaClient,
        int estimatedSize)
            throws GeneralSecurityException, IOException, DocumentException {

      // Creating the reader and the stamper
      PdfReader reader = new PdfReader(src);
      FileOutputStream os = new FileOutputStream(dest);
      PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
      // Creating the appearance
      PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
      appearance.setReason(reason);
      appearance.setLocation(location);
      appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
      // Creating the signature
      ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm,
          signatureProvider);
      ExternalDigest digest = new ProviderDigest(mdProvider);
      MakeSignature.signDetached(appearance, digest, pks, chain, crlList, ocspClient,
          tsaClient, estimatedSize, subfilter);
    }
  }

}
