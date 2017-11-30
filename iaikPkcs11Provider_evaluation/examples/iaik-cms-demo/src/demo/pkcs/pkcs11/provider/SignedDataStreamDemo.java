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

// class and interface imports
import iaik.asn1.structures.AlgorithmID;
import iaik.cms.CMSException;
import iaik.cms.IssuerAndSerialNumber;
import iaik.cms.SecurityProvider;
import iaik.cms.SignedDataStream;
import iaik.cms.SignerInfo;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * Base class of SignedDataStream demos using PKCS#11 for accessing the signer key on a smart card.
 */
public class SignedDataStreamDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The name of the file that contains the data to be signed.
   */
  protected String fileToBeSigned_;

  /**
   * The name of the signed file.
   */
  protected String outputFile_;

  /**
   * The key store that represents the token (smart card) contents.
   */
  protected KeyStore tokenKeyStore_;

  /**
   * The signature key. In this case only a proxy object, but the application cannot see this.
   */
  protected PrivateKey signatureKey_;

  /**
   * This is the certificate used for verifying the signature. In contrast to the signature key,
   * this key holds the actual keying material.
   */
  protected X509Certificate signerCertificate_;

  /**
   * Creates a SignedDataStreamDemo object for the given module name.
   * 
   * @param moduleName
   *          the name of the module
   * @param userPin
   *          the user-pin (password) for the TokenKeyStore (may be <code>null</code> to pou-up a
   *          dialog asking for the pin)
   */
  protected SignedDataStreamDemo(String fileToBeSigned, String outputFile) {
    fileToBeSigned_ = fileToBeSigned;
    outputFile_ = outputFile;

    // special care is required during the registration of the providers
    pkcs11Provider_ = new IAIKPkcs11();
    // IAIKPkcs11.insertProviderAtForJDK14(pkcs11Provider_, 1); // add IAIK PKCS#11 JCE provider as
    // first, use JDK 1.4 bug workaround

    iaikSoftwareProvider_ = new IAIK();
    Security.addProvider(iaikSoftwareProvider_); // add IAIK softweare JCE provider
    Security.addProvider(pkcs11Provider_);

    // set CMS security provider
    IaikPkcs11SecurityProvider pkcs11CmsSecurityProvider = new IaikPkcs11SecurityProvider(
        pkcs11Provider_);
    SecurityProvider.setSecurityProvider(pkcs11CmsSecurityProvider);

  }

  /**
   * This method gets the key store of the PKCS#11 provider and stores a reference at
   * <code>pkcs11ClientKeystore_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getKeyStore() throws GeneralSecurityException, IOException {
    KeyStore tokenKeyStore = null;
    tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore", pkcs11Provider_.getName());

    if (tokenKeyStore == null) {
      System.out
          .println("Got no key store. Ensure that the provider is properly configured and installed.");
      throw new GeneralSecurityException("Got no key store.");
    }
    tokenKeyStore.load(null, null); // this call binds the keystore to the first instance of the
                                    // IAIKPkcs11 provider

    tokenKeyStore_ = tokenKeyStore;
  }

  /**
   * This method gets the key stores of all inserted (compatible) smart cards and simply takes the
   * first key-entry. From this key entry it takes the private key and the certificate to retrieve
   * the public key from. The keys are stored in the member variables <code>signerKey_
   * </code> and <code>signerCertificate_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  protected void getSignatureKey(String alias) throws GeneralSecurityException,
      IOException {

    if (alias == null) {
      // we simply take the first keystore, if there are serveral
      Enumeration aliases = tokenKeyStore_.aliases();

      // and we take the first signature (private) key for simplicity
      while (aliases.hasMoreElements()) {
        String keyAlias = aliases.nextElement().toString();
        Key key = null;
        try {
          key = tokenKeyStore_.getKey(keyAlias, null);
        } catch (NoSuchAlgorithmException ex) {
          throw new GeneralSecurityException(ex.toString());
        }

        if (key instanceof PrivateKey) {
          Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
          if ((certificateChain != null) && (certificateChain.length > 0)) {
            X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
            boolean[] keyUsage = signerCertificate.getKeyUsage();
            if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature
                                                                    // or non-repudiation, but also
                                                                    // accept if none set
              System.out.println("##########");
              System.out.println("The signer key is: " + key);
              System.out.println("##########");
              // get the corresponding certificate for this signer key
              System.out.println("##########");
              System.out.println("The signer certificate is:");
              System.out.println(signerCertificate.toString());
              System.out.println("##########");
              signatureKey_ = (PrivateKey) key;
              signerCertificate_ = signerCertificate;
              break;
            }
          }
        }
      }

    } else {
      System.out.println("using signature key with alias: " + alias);
      signatureKey_ = (PrivateKey) tokenKeyStore_.getKey(alias, null);
      signerCertificate_ = (X509Certificate) tokenKeyStore_.getCertificate(alias);
    }

    if (signatureKey_ == null) {
      System.out
          .println("Found no signature key. Ensure that a valid card is inserted and contains a key that is suitable for signing.");
      throw new GeneralSecurityException("Found no signature key.");
    } else {
      System.out.println("##########");
      System.out.println("The signature key is: " + signatureKey_);
      System.out.println("##########");
      // get the corresponding certificate for this signature key
      System.out.println("##########");
      System.out.println("The signer certificate is:");
      System.out.println(signerCertificate_.toString());
      System.out.println("##########");
    }
  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with <code>signatureKey_</code>.
   * Normally the data would be read from file. The created signature is stored in
   * <code>signature_</code>.
   * 
   * @param data
   *          the data to be signed
   * @param implicit
   *          whether to include the data (implicit mode) or to not include it (explicit mode)
   * @return the encoded SignedData
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If the data file could not be found or writing to it failed.
   * @exception CMSException
   *              If an error occurs when creating/encoding the SignedData
   */
  public void sign(boolean implicit) throws GeneralSecurityException, IOException,
      CMSException {
    System.out.println("##########");
    System.out.print("Signing data... ");

    FileInputStream dataStream = new FileInputStream(fileToBeSigned_); // the raw data supplying
                                                                       // input stream
    int mode = (implicit == true) ? SignedDataStream.IMPLICIT : SignedDataStream.EXPLICIT;
    SignedDataStream signedData = new SignedDataStream(dataStream, mode);
    iaik.x509.X509Certificate iaikSignerCertificate = (signerCertificate_ instanceof iaik.x509.X509Certificate) ? (iaik.x509.X509Certificate) signerCertificate_
        : new iaik.x509.X509Certificate(signerCertificate_.getEncoded());
    signedData.setCertificates(new iaik.x509.X509Certificate[] { iaikSignerCertificate });
    IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(
        iaikSignerCertificate);
    SignerInfo signerInfo = new SignerInfo(issuerAndSerialNumber,
        (AlgorithmID) AlgorithmID.sha1.clone(), signatureKey_);
    try {
      signedData.addSignerInfo(signerInfo);
    } catch (NoSuchAlgorithmException ex) {
      throw new GeneralSecurityException(ex.toString());
    }

    if (implicit == false) {
      // in explicit mode read "away" content data (to be transmitted out-of-band)
      InputStream contentIs = signedData.getInputStream();
      byte[] buffer = new byte[2048];
      int bytesRead;
      while ((bytesRead = contentIs.read(buffer)) >= 0) {
        ; // skip data
      }
    }

    FileOutputStream outputStream = new FileOutputStream(outputFile_);
    signedData.writeTo(outputStream);
    outputStream.flush();
    outputStream.close();

    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @param encodedSignedData
   *          the encoded SignedData object
   * @param contentData
   *          the contentData (in explicit mode required for signature verification)
   * @return the content data
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If reading the CMS file fails.
   * @exception CMSException
   *              If handling the CMS structure fails.
   * @exception SignatureException
   *              If the signature verification fails
   */
  public byte[] verify() throws GeneralSecurityException, CMSException, IOException,
      SignatureException {
    System.out.println("##########");
    System.out.println("Verifying signature");

    InputStream inputStream = new FileInputStream(outputFile_);
    SignedDataStream signedData = new SignedDataStream(inputStream);

    if (signedData.getMode() == SignedDataStream.EXPLICIT) {
      // explicitly set the data received by other means
      signedData.setInputStream(new FileInputStream(fileToBeSigned_));
    }

    // read data
    InputStream signedDataInputStream = signedData.getInputStream();

    ByteArrayOutputStream contentOs = new ByteArrayOutputStream();
    byte[] buffer = new byte[2048];
    int bytesRead;
    while ((bytesRead = signedDataInputStream.read(buffer)) >= 0) {
      contentOs.write(buffer, 0, bytesRead);
    }

    // get the signer infos
    SignerInfo[] signerInfos = signedData.getSignerInfos();
    // verify the signatures
    for (int i = 0; i < signerInfos.length; i++) {
      try {
        // verify the signature for SignerInfo at index i
        X509Certificate signerCertificate = signedData.verify(i);
        // if the signature is OK the certificate of the signer is returned
        System.out.println("Signature OK from signer: "
            + signerCertificate.getSubjectDN());
      } catch (SignatureException ex) {
        // if the signature is not OK a SignatureException is thrown
        throw new SignatureException("Signature ERROR: " + ex.getMessage());
      }
    }
    System.out.println("##########");
    // return the content
    return contentOs.toByteArray();
  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   */
  public static void main(String[] args) throws Exception {

    if (args.length < 3) {
      printUsage();
      throw new Exception("missing arguments");
    }
    String fileToBeSigned = args[0];
    String outputFile = args[1];

    SignedDataStreamDemo demo = new SignedDataStreamDemo(fileToBeSigned, outputFile);

    demo.getKeyStore();
    demo.getSignatureKey((args.length < 4) ? null : args[3]);
    boolean implicit = args[2].equalsIgnoreCase("implicit");
    demo.sign(implicit);
    demo.verify();
    System.out.flush();
    System.err.flush();

  }

  /**
   * Print information how to use this demo class.
   */
  public static void printUsage() {
    System.out
        .println("Usage: SignedDataStreamDemo <file to sign> <output file> <implicit|explicit> [<keyAlias>]");
    System.out
        .println(" e.g.: SignedDataStreamDemo contract.rtf signedContract.p7 explicit MaxMustermann");
  }

}
