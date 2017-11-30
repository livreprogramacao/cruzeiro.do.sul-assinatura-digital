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

import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CertificateIdentifier;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.KeyTransRecipientInfo;
import iaik.cms.RecipientInfo;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

/**
 * This helper class encrypts the given data using TrippleDES and encrypts the symmetric key using
 * the public key in the given certificate.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class CreateEnvelopedData {

  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      printUsage();
      throw new Exception("missing arguments");
    }

    Security.addProvider(new IAIK());

    System.out.println("Encrypting data from file: " + args[0]);
    InputStream dataInputStream = new FileInputStream(args[0]);

    EnvelopedDataStream envelopedData = new EnvelopedDataStream(dataInputStream,
        AlgorithmID.des_EDE3_CBC);

    System.out.println("using recipient certificate from: " + args[1]);
    InputStream certificateInputStream = new FileInputStream(args[1]);

    X509Certificate recipientCertificate = new X509Certificate(certificateInputStream);
    System.out.println("which is: ");
    System.out.println(recipientCertificate.toString(true));

    RecipientInfo recipient = new KeyTransRecipientInfo(recipientCertificate,
        CertificateIdentifier.ISSUER_AND_SERIALNUMBER, AlgorithmID.rsaEncryption);

    envelopedData.setRecipientInfos(new RecipientInfo[] { recipient });

    System.out.println("writing enveloped data to: " + args[2]);
    OutputStream envelopedDataOutputStream = new FileOutputStream(args[2]);
    envelopedData.writeTo(envelopedDataOutputStream);

  }

  public static void printUsage() {
    System.out
        .println("Usage: CreateEnvelopedData <data to encrypt file> <recipient certificate> <CMS enveloped data file>");
    System.out
        .println(" e.g.: CreateEnvelopedData contentData.dat recipientCertificte.der envelopedData.p7");
  }

}
