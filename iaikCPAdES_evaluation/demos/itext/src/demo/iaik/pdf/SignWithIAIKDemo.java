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

import iaik.pdf.itext.MakeSignatureIAIK;
import iaik.security.provider.IAIK;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;

/**
 * This demo shows how to sign a PDF document using MakeSignatureIAIK. This alternative
 * implementation of iText's MakeSignature class uses IAIK implementations for message digest,
 * signature, OCSP response, timestamp and CMS signature creation. The demo uses private key and
 * certificate chain of a PKCS#12 file.
 */

public class SignWithIAIKDemo {

  /**
   * Registers IAIK JCE provider and starts demo.
   * 
   * @param args
   *          PKCS#12 file name and password, TSA URL is optional
   */
  public static void main(String[] args) throws Exception {
    if (args == null || args.length < 2) {
      printUsage();
    } else {
      LoggerFactory.getInstance().setLogger(new SysoLogger());

      // for signing
      Security.addProvider(new IAIK());
      // for verifying
      Security.addProvider(new BouncyCastleProvider());

      SignWithIAIKDemo demo = new SignWithIAIKDemo();
      if (args.length > 2)
        demo.startSigningDemo(args[0], args[1], args[2]);
      else
        demo.startSigningDemo(args[0], args[1], null);
    }
  }

  /**
   * sign PDF document
   * 
   * @param pathToKey
   *          path to PKCS#12 file
   * @param pw
   *          password for PKCS#12 file
   * @param tsaUrl
   *          URL to timestamp server to create timestamp
   * @throws Exception
   *           in case of any exceptions
   */
  public void startSigningDemo(String pathToKey, String pw, String tsaUrl)
      throws Exception {

    String pdfToBeSigned = "test.pdf";
    String fileToBeVerified = "test_signed_signed.pdf";

    // load PKCS#12 file
    FileInputStream fis = new FileInputStream(pathToKey);
    KeyStore store = KeyStore.getInstance("PKCS12", "IAIK");
    store.load(fis, pw.toCharArray());

    // find suitable key with certificate chain
    Enumeration<String> aliases = store.aliases();
    String alias = null;
    while (aliases.hasMoreElements()) {
      String curAlias = aliases.nextElement();
      if (store.isKeyEntry(curAlias) && store.getCertificateChain(curAlias) != null) {
        alias = curAlias;
        break;
      }
    }
    if (alias == null)
      throw new IOException("no suitable signature key found");

    PrivateKey pk = (PrivateKey) store.getKey(alias, pw.toCharArray());
    Certificate[] chain = store.getCertificateChain(alias);

    fis.close();

    // add timestamp if TSA URL is available
    if (tsaUrl == null) {
      for (int i = 0; i < chain.length; i++) {
        X509Certificate cert = (X509Certificate) chain[i];
        tsaUrl = CertificateUtil.getTSAURL(cert);
        if (tsaUrl != null) {
          break;
        }
      }
    }

    // include CRLs in signature - let iText extract the CRLs
    List<CrlClient> crlList = new ArrayList<CrlClient>();
    crlList.add(new CrlClientOnline());

    // specify, whether an OCSP response shall be included
    boolean useOcsp = true;

    // sign 'test.pdf', save signed PDF to 'test-signed.pdf'
    MakeSignatureIAIK.signDetached(pdfToBeSigned, fileToBeVerified, chain, pk,
        DigestAlgorithms.SHA256, CryptoStandard.CMS, "sign test", "Graz", crlList,
        useOcsp, tsaUrl, null, null, 0);

    verifyPdf(fileToBeVerified);

    System.out.println("finished");
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
      System.out.println(name + ": " + af.signatureCoversWholeDocument(name));
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
      StringBuffer namesString = new StringBuffer();
      for (String signatureName : invalidSignatures) {
        namesString.append(signatureName);
        namesString.append(", ");
      }
      namesString.deleteCharAt(namesString.length() - 1);
      throw new GeneralSecurityException(
          "the signatures " + namesString.toString() + " are invalid!");
    }
    return true;

  }

  public static void printUsage() {
    System.out.println(
        "Usage: SignWithIAIKDemo <PKCS#12 file> <password for PKCS#12 file> [<tsaUrl>]");
    System.out.println(" e.g.: SignWithIAIKDemo mykeys.p12 password");
  }

}
