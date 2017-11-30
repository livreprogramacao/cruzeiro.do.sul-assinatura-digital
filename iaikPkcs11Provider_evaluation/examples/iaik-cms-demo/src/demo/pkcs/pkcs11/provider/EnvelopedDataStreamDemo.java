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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

import iaik.cms.CMSException;
import iaik.cms.EnvelopedDataStream;
import iaik.cms.KeyIdentifier;
import iaik.cms.RecipientInfo;
import iaik.cms.SecurityProvider;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;

/**
 * This class shows how to decrypt data according to CMS using the PKCS#11 provider. This
 * implementation uses the <code>SecurityProvider</code> feature of the CMS implementation of the
 * IAIK-CMS toolkit.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class EnvelopedDataStreamDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The name of the file that contains the data to be decrypted.
   */
  protected String fileToBeDecrypted_;

  /**
   * The CMS object for handling the encrypted data.
   */
  protected EnvelopedDataStream envelopedData_;

  /**
   * The CMS recipient info for our decryption key.
   */
  protected RecipientInfo recipientInfo_;

  /**
   * The CMS recipient info index for our decryption key.
   */
  protected int recipientInfoIndex_;

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
  protected PrivateKey decryptionKey_;

  /**
   * This is the certificate used for verifying the signature. In contrast to the signature key,
   * this key holds the actual keying material.
   */
  protected X509Certificate decryptionCertificate_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public EnvelopedDataStreamDemo(String fileToBeDecrypted, String outputFile) {
    fileToBeDecrypted_ = fileToBeDecrypted;
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

    System.out.println("Installed security providers providers:");
    System.out.println();
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      Provider provider = providers[i];
      System.out.println("Provider " + (i + 1) + ": " + provider.getName()
          + "  version: " + provider.getVersion());
    }
  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      printUsage();
      throw new Exception("missing arguments");
    }
    String fileToBeDecrypted = args[0];
    String outputFile = args[1];

    EnvelopedDataStreamDemo demo = new EnvelopedDataStreamDemo(fileToBeDecrypted,
        outputFile);

    demo.getKeyStore();
    demo.getDecryptionKey();
    demo.decrypt();
    System.out.flush();
    System.err.flush();
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
    // with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
    // specific IAIKPkcs11 provider instance after this call, even if you specify the provider
    // at this call. this is a limitation of SUN's KeyStore concept. the KeyStoreSPI object
    // has no chance to get its own provider instance.
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");

    if (tokenKeyStore == null) {
      System.out
          .println("Got no key store. Ensure that the provider is properly configured and installed.");
      throw new GeneralSecurityException("got no key store");
    }
    tokenKeyStore.load(null, null); // this call binds the keystore to the first instance of the
                                    // IAIKPkcs11 provider
    // if you want ot bind it to a different instance, you have to provide the provider name as
    // stream
    // see the other RSASigningDemo classes for examples

    tokenKeyStore_ = tokenKeyStore;
  }

  /**
   * This method gets the key store of the PKCS#11 provider and searches for a private key antry
   * that can decrypt the CMS data. If it finds such a key, it stores information about this hit in
   * some memeber varaibles.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   * @exception CMSException
   *              If parsing the CMS data fails.
   */
  public void getDecryptionKey() throws GeneralSecurityException, IOException,
      CMSException {
    // read the CMS file
    FileInputStream inputData = new FileInputStream(fileToBeDecrypted_);
    envelopedData_ = new EnvelopedDataStream(inputData);

    RecipientInfo[] recipientInfos = envelopedData_.getRecipientInfos();
    System.out.println("Included RecipientInfos: ");
    for (int recipientIndex = 0; recipientIndex < recipientInfos.length; recipientIndex++) {
      System.out.print("Recipient Info " + (recipientIndex + 1) + ": ");
      KeyIdentifier[] keyIdentifiers = recipientInfos[recipientIndex]
          .getRecipientIdentifiers();
      for (int keyIdentifierIndex = 0; keyIdentifierIndex < keyIdentifiers.length; keyIdentifierIndex++) {
        System.out.print(keyIdentifiers[keyIdentifierIndex]);
      }
      System.out.println();
    }

    // we simply take the first keystore, if there are serveral
    Enumeration aliases = tokenKeyStore_.aliases();

    // and we take the first signature (private) key for simplicity
    whileloop: while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = tokenKeyStore_.getKey(keyAlias, null);
      if (key instanceof RSAPrivateKey) {
        Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
        if (certificateChain != null && certificateChain.length > 0) {
          X509Certificate userCertificate = (X509Certificate) certificateChain[0];
          boolean[] keyUsage = userCertificate.getKeyUsage();
          if ((keyUsage == null) || keyUsage[2] || keyUsage[3]) { // check for encryption, but also
                                                                  // accept if none set
            // check if there is a receipient info for this certificate
            iaik.x509.X509Certificate iaikUserCertificate = (userCertificate instanceof iaik.x509.X509Certificate) ? (iaik.x509.X509Certificate) userCertificate
                : new iaik.x509.X509Certificate(userCertificate.getEncoded());
            for (int i = 0; i < recipientInfos.length; i++) {
              if (recipientInfos[i].isRecipientInfoFor(iaikUserCertificate) != null) {
                System.out.println("##########");
                System.out.println("The decrpytion key is: " + key);
                System.out.println("##########");
                // get the corresponding certificate for this signature key
                System.out.println("##########");
                System.out.println("The decryption certificate is:");
                System.out.println(userCertificate.toString());
                System.out.println("##########");
                decryptionKey_ = (PrivateKey) key;
                decryptionCertificate_ = userCertificate;
                recipientInfo_ = recipientInfos[i];
                recipientInfoIndex_ = i;
                break whileloop;
              }
            }
          }
        }
      }
    }

    if (decryptionKey_ == null) {
      System.out
          .println("Found no decryption key. Ensure that the correct card is inserted.");
      throw new GeneralSecurityException("found no decryption key");
    }
  }

  /**
   * This method decrypts the data from the provided encrypted CMS file. It uses the info in the
   * member variables set by <code>getDecryptionKey()</code>. Moreover, it writes the decrypted data
   * to the specified output file.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception FileNotFoundException
   *              If the data file could not be found.
   * @exception CMSException
   *              If handling the CMS data fails.
   */
  public void decrypt() throws GeneralSecurityException, IOException, CMSException {
    System.out.println("##########");
    System.out.print("Decrypting data... ");

    // setup cipher engine for decryption
    envelopedData_.setupCipher(decryptionKey_, recipientInfoIndex_);

    // read all data and write to output file
    FileOutputStream outputStream = new FileOutputStream(outputFile_);
    InputStream dataInput = envelopedData_.getInputStream();
    byte[] buffer = new byte[4096];
    int bytesRead;
    while ((bytesRead = dataInput.read(buffer)) >= 0) {
      // write to output
      outputStream.write(buffer, 0, bytesRead);
    }

    outputStream.flush();
    outputStream.close();

    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * Print information how to use this demo class.
   */
  public static void printUsage() {
    System.out.println("Usage: EvelopedDataStreamDemo <file to decrypt> <output file>");
    System.out
        .println(" e.g.: EvelopedDataStreamDemo encryptedData.p7 decryptedData.dat");
  }

}
