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
import iaik.cms.SignedData;
import iaik.pdf.asn1objects.SignatureTimeStamp;
import iaik.pdf.cmscades.CadesSignature;
import iaik.pdf.cmscades.CadesSignatureStream;
import iaik.pdf.cmscades.CmsCadesException;
import iaik.pdf.parameters.CadesTParameters;
import iaik.security.provider.IAIK;
import iaik.tsp.TspVerificationException;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Enumeration;
import java.util.Random;

/**
 * This demo shows how to create CAdES signatures using the class CadesSignature or
 * CadesSignatureStream and appropriate parameters.
 */
public class CadesSignatureDemo {

  static String fileToBeSigned = "contract.txt";
  static String signatureFile = "contractsigned.ber";

  private PrivateKey privKey_;
  private X509Certificate[] certChain_;

  /**
   * Add required IAIK JCE provider.
   */
  public CadesSignatureDemo() {
    Security.addProvider(new IAIK());
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
    fis.close();
  }

  /**
   * Signs data given as byte array. By using parameters of type CadesBESParameters a CAdES
   * signature according to CAdES-BES will be created. For a CAdES-T signature use a
   * CadesTParameters instance.
   * 
   * @param data
   *          data to be signed
   * @return the encoded CAdES signature
   * @throws CmsCadesException
   *           if errors during signature creation occurred
   * @throws GeneralSecurityException
   *           if the specified digest algorithm is not available
   * @throws IOException
   *           if data can't be read
   */
  private byte[] signData(byte[] data)
      throws CmsCadesException, GeneralSecurityException, IOException {
    CadesSignature cmsSig = new CadesSignature(data, SignedData.EXPLICIT);
    // CadesBESParameters params = new CadesBESParameters();
    CadesTParameters params = new CadesTParameters(
        "http://tsp.iaik.tugraz.at/tsp/TspRequest", null, null);
    params.setDigestAlgorithm("SHA512");
    cmsSig.addSignerInfo(privKey_, certChain_, params);
    return cmsSig.encodeSignature();
  }

  /**
   * Shows some possible verification steps, i.e. verifies the signature value and the timestamp if
   * included.
   * 
   * @param signature
   *          encoded cades signature
   * @param data
   *          data, that has been signed with the given signature
   * @throws CmsCadesException
   *           if errors occurred during signature verification
   * @throws TspVerificationException
   *           if errors occurred during timestamp verification
   */
  private void verifyCadesSignature(byte[] signature, byte[] data)
      throws CmsCadesException, TspVerificationException, CMSSignatureException {
    CadesSignature cadesSig = new CadesSignature(signature, data);
    int signerInfoLength = cadesSig.getSignerInfos().length;

    System.out.println("Signature contains " + signerInfoLength + " signer infos");

    for (int j = 0; j < signerInfoLength; j++) {
      cadesSig.verifySignatureValue(j);
      System.out.println("Signer " + (j + 1) + " signature value is valid.");

      // tsp verification
      SignatureTimeStamp[] timestamps = cadesSig.getSignatureTimeStamps(j);
      for (SignatureTimeStamp tst : timestamps) {
        System.out.println("Signer info " + (j + 1) + " contains a signature timestamp.");
        tst.verifyTimeStampToken(null);
        System.out.println("Signer info " + (j + 1) + " signature timestamp is valid.");
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
   * @param signatureFilename
   *          file name to use for saving the CAdES signature
   * @throws CmsCadesException
   *           if errors during signature creation occurred
   * @throws GeneralSecurityException
   *           if the specified digest algorithm is not available
   * @throws IOException
   *           if data can't be read
   */
  private void signDataStream(InputStream data, String signatureFilename)
      throws CmsCadesException, GeneralSecurityException, IOException {
    CadesSignatureStream cmsSig = new CadesSignatureStream(data, SignedData.EXPLICIT);
    // CadesBESParameters params = new CadesBESParameters();
    CadesTParameters params = new CadesTParameters(
        "http://tsp.iaik.tugraz.at/tsp/TspRequest", null, null);
    params.setDigestAlgorithm("SHA512");
    cmsSig.addSignerInfo(privKey_, certChain_, params);
    ByteArrayOutputStream signature = new ByteArrayOutputStream();
    cmsSig.encodeSignature(signature);
    byte[] signatureBytes = signature.toByteArray();
    signature.close();
    FileOutputStream os = new FileOutputStream(signatureFilename);
    os.write(signatureBytes);
    os.flush();
    os.close();
  }

  /**
   * Shows some possible verification steps, i.e. verifies the signature value and the timestamp if
   * included.
   * 
   * @param signature
   *          cades signature stream
   * @param data
   *          data, that has been signed with the given signature
   * @throws CmsCadesException
   *           if errors occurred during signature verification
   * @throws TspVerificationException
   *           if errors occurred during timestamp verification
   */
  private void verifyCadesSignatureStream(InputStream signature, InputStream data)
      throws CmsCadesException, TspVerificationException, CMSSignatureException {
    CadesSignatureStream cadesSig = new CadesSignatureStream(signature, data);
    int signerInfoLength = cadesSig.getSignerInfos().length;

    System.out.println("Signature contains " + signerInfoLength + " signer infos");

    for (int j = 0; j < signerInfoLength; j++) {
      cadesSig.verifySignatureValue(j);
      System.out.println("Signer " + (j + 1) + " signature value is valid.");

      // tsp verification
      SignatureTimeStamp[] timestamps = cadesSig.getSignatureTimeStamps(j);
      for (SignatureTimeStamp tst : timestamps) {
        System.out.println("Signer info " + (j + 1) + " contains a signature timestamp.");
        tst.verifyTimeStampToken(null);
        System.out.println("Signer info " + (j + 1) + " signature timestamp is valid.");
      }
    }
  }

  /**
   * Shows how to create CAdES signatures for some random bytes and a given file. Verifies the
   * created signatures.
   * 
   * @param filePath
   *          path to the PKCS#12 file
   * @param password
   *          password of the PKCS#12 file
   * @throws CmsCadesException
   *           if errors occur during signature creation and verification
   * @throws GeneralSecurityException
   *           if the required digest algorithm is not available
   * @throws IOException
   *           if I/O errors occur
   * @throws TspVerificationException
   *           if errors occur during timestamp verification
   */
  private void start(String filePath, String password) throws CmsCadesException,
      GeneralSecurityException, IOException, TspVerificationException {
    getKeyAndCerts(filePath, password);

    // sign some bytes
    byte[] somerandomdata = new byte[100];
    Random random = new Random();
    random.nextBytes(somerandomdata);
    byte[] signature = signData(somerandomdata);
    System.out.println("signed some random data");

    System.out.println("verify the signature: ");
    verifyCadesSignature(signature, somerandomdata);

    // sign a file stream
    FileInputStream dataStream = new FileInputStream(fileToBeSigned);
    signDataStream(dataStream, signatureFile);
    dataStream.close();
    System.out.println(
        "signed file " + fileToBeSigned + " and saved signature to " + signatureFile);

    System.out.println("verify the signature contained in " + signatureFile + ":");
    FileInputStream sigStream = new FileInputStream(signatureFile);
    dataStream = new FileInputStream(fileToBeSigned);
    verifyCadesSignatureStream(sigStream, dataStream);
    sigStream.close();
    dataStream.close();
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
      CadesSignatureDemo demo = new CadesSignatureDemo();
      demo.start(args[0], args[1]);
    }
  }

  public static void printUsage() {
    System.out
        .println("Usage: CadesSignatureDemo <PKCS#12 file> <password for PKCS#12 file>");
    System.out.println(" e.g.: CadesSignatureDemo mykeys.p12 password");
  }

}
