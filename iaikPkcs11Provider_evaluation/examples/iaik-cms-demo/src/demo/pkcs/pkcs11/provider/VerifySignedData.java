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
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.security.SignatureException;

import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

/**
 * This helper class simply verifies the signature of a CMS signed data object and extracts the
 * verified content data (if included, i.e. if implicitly signed).
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class VerifySignedData {

  public static void main(String[] args) throws Exception {
    if ((args.length < 1)) {
      printUsage();
      throw new Exception("missing arguments");
    }

    Security.addProvider(new IAIK());

    System.out.println("Verifying CMS signed data from file: " + args[0]);
    InputStream dataInput = new FileInputStream(args[0]);

    SignedDataStream signedData = new SignedDataStream(dataInput);

    if (args.length > 2) {
      // explicitly set the data received by other means
      signedData.setInputStream(new FileInputStream(args[2]));
    }

    InputStream contentStream = signedData.getInputStream();
    OutputStream verifiedContentStream = (args.length > 1) ? new FileOutputStream(args[1])
        : null;
    byte[] buffer = new byte[1024];
    int bytesRead;

    if (verifiedContentStream != null) {
      while ((bytesRead = contentStream.read(buffer)) > 0) {
        verifiedContentStream.write(buffer, 0, bytesRead);
      }
      verifiedContentStream.flush();
      verifiedContentStream.close();
      System.out.println("Verified content written to: " + args[1]);
      System.out
          .println("________________________________________________________________________________");
    } else {
      System.out.println("The signed content data is: ");
      System.out
          .println("________________________________________________________________________________");
      while ((bytesRead = contentStream.read(buffer)) > 0) {
        System.out.write(buffer, 0, bytesRead);
      }
      System.out.println();
      System.out
          .println("________________________________________________________________________________");
    }

    // get the signer infos
    SignerInfo[] signerInfos = signedData.getSignerInfos();
    // verify the signatures
    for (int i = 0; i < signerInfos.length; i++) {
      try {
        // verify the signature for SignerInfo at index i
        X509Certificate signerCertificate = signedData.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer with certificate: ");
        System.out.println(signerCertificate);
        System.out.println();
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        System.out.println("Signature ERROR from signer with certificate: ");
        System.out
            .println(signedData.getCertificate(signerInfos[i].getSignerIdentifier()));
        System.out.println();
        throw ex;
      }
    }

  }

  public static void printUsage() {
    System.out
        .println("Usage: VerifySignedData <CMS signed data file> [<verified content file> <original data>]");
    System.out.println(" e.g.: VerifySignedData signedData.p7 verifiedContentData.dat");
  }

}
