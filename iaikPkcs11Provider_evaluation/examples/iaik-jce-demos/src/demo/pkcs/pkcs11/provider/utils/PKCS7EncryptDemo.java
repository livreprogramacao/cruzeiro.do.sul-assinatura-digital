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

package demo.pkcs.pkcs11.provider.utils;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs7.ContentInfoStream;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;

/**
 * This class shows some PKCS#7 examples and uses the stream interface for processing large amounts
 * of data.
 * <p>
 * All keys and certificates are read from a keystore created by the SetupKeyStore program.
 * <p>
 * This class tests the following PKCS#7 content type implementations:
 * <p>
 * <ul>
 * <li>EnvelopedData
 * <li>SignedData including the message
 * <li>SignedData without message
 * <li>SignedAndEnvelopedData
 * </ul>
 * <p>
 * Additionally, a <i>SignedAndEncryptedData</i> test is performed, which is a sequential
 * combination of signed and enveloped data and should be prefered to the
 * <code>SignedAndEnvelopedData</code> content type.
 * <p>
 * All sub-tests use the same proceeding: A test message is properly processed to give the requested
 * content type object, which subsequently is DER encoded to be "sent" to some recipient, who parses
 * it for the inherent structures.
 * 
 */
public class PKCS7EncryptDemo {

  X509Certificate user1;

  /**
   * Setup the demo certificate chains. Keys and certificate are retrieved from the demo KeyStore.
   * 
   * @exception IOException
   *              if an file read error occurs
   */
  public PKCS7EncryptDemo(String recipientCertPath) throws IOException,
      CertificateException {
    Security.addProvider(new IAIK());
    InputStream certificateInputStream = new FileInputStream(recipientCertPath);
    user1 = new X509Certificate(certificateInputStream);
    certificateInputStream.close();
  }

  /**
   * Creates a PKCS#7 <code>EnvelopedDataStream</code> message.
   * <p>
   * The enveloped-data content type consists of encrypted content of any type and encrypted
   * content-encryption keys for one or more recipients. The combination of encrypted content and
   * encrypted content-encryption key for a recipient is a "digital envelope" for that recipient.
   * Any type of content can be enveloped for any number of recipients in parallel.
   * 
   * @param message
   *          the message to be enveloped, as byte representation
   * @return the DER encoded ContentInfo containing the EnvelopedData object just created
   * @exception PKCSException
   *              if the <code>EnvelopedData</code> object cannot be created
   */
  public void createEnvelopedDataStream(byte[] message, String fileName)
      throws PKCSException, IOException {

    EnvelopedDataStream enveloped_data;

    // we are testing the stream interface
    ByteArrayInputStream is = new ByteArrayInputStream(message);
    // create a new EnvelopedData object encrypted with TripleDES CBC
    try {
      enveloped_data = new EnvelopedDataStream(is, AlgorithmID.des_EDE3_CBC);
    } catch (NoSuchAlgorithmException ex) {
      throw new PKCSException("No implementation for Triple-DES-CBC.");
    }

    try {
      // create the recipient infos
      RecipientInfo[] recipients = new RecipientInfo[1];
      // user1 is the first receiver
      recipients[0] = new RecipientInfo(user1, AlgorithmID.rsaEncryption);

      // specify the recipients of the encrypted message
      enveloped_data.setRecipientInfos(recipients);
    } catch (NoSuchAlgorithmException ex) {
      throw new PKCSException(ex.toString());
    }

    // return the EnvelopedData as DER encoded byte array with block size 2048
    FileOutputStream fos = new FileOutputStream(fileName);
    enveloped_data.setBlockSize(2048);
    ContentInfoStream cis = new ContentInfoStream(enveloped_data);
    cis.writeTo(fos);
  }

  /**
   * Tests the PKCS#7 content type implementations <code>EnvelopedData</code>,
   * <code>SignedData</code>, and <code>SignedAndEnvelopedData</code>. An additional
   * <i>SignedAndEncryptedData</i> test sequentially combines signed and enveloped data, which
   * should be prefered to the <code>SignedAndEnvelopedData</code> content type.
   */
  public void start(String fileName) throws IOException, PKCSException,
      GeneralSecurityException {
    // the test message
    String m = "This is the test message.";
    System.out.println("Test message: \"" + m + "\"");
    System.out.println();
    byte[] message = m.getBytes();

    System.out.println("\nEnvelopedDataStream demo [create]:\n");
    createEnvelopedDataStream(message, fileName);
    System.out.println("Enveloped data written to " + fileName);

  }

  /**
   * Starts the PKCS#7 content type implementation tests.
   * 
   * @exception IOException
   *              if an I/O error occurs when reading required keys and certificates from files
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      printUsage();
      throw new GeneralSecurityException("incorrect parameters");
    }

    PKCS7EncryptDemo demo = new PKCS7EncryptDemo(args[0]);
    demo.start(args[1]);
  }

  /**
   * Print information how to use this demo class.
   */
  public static void printUsage() {
    System.out
        .println("Usage: PKCS7EncryptDemo <recipientCertificatePath> <output file>");
    System.out
        .println(" e.g.: PKCS7EncryptDemo recipientCertificte.der envelopedData.p7");
  }

}
