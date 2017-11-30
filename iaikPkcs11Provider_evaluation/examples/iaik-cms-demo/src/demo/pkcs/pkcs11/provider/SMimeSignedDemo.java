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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.activation.MailcapCommandMap;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;

import iaik.cms.SecurityProvider;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SignedContent;
import iaik.x509.X509Certificate;

/**
 * This example demonstrates how to create a signed S/MIME message and send it. It uses a PKCS#11
 * module (e.g. a smart card) to create the signature. This implementation uses the
 * <code>SecurityProvider</code> feature of the CMS implementation of the IAIK-CMS toolkit.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SMimeSignedDemo {

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
   * The email address of the sender.
   */
  protected String sender_;

  /**
   * The email address of the recipient.
   */
  protected String recipient_;

  /**
   * The name of the SMTP server.
   */
  protected String smtpServer_;

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
   * This empty constructor registers the new provider to the Java security system.
   */
  public SMimeSignedDemo(String fileToBeSigned, String sender, String recipient,
      String smtpServer) {
    fileToBeSigned_ = fileToBeSigned;
    sender_ = sender;
    recipient_ = recipient;
    smtpServer_ = smtpServer;

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
    if (args.length < 5) {
      printUsage();
      throw new Exception("missing arguments");
    }
    String fileToBeSigned = args[0];
    String sender = args[1];
    String recipient = args[2];
    String smtpServer = args[3];

    SMimeSignedDemo demo = new SMimeSignedDemo(fileToBeSigned, sender, recipient,
        smtpServer);

    demo.getKeyStore();
    demo.getSignatureKey((args.length < 6) ? null : args[5]);
    demo.createMessage(args[4]);
    System.out.flush();
    System.err.flush();
  }

  /**
   * This method gets the key store of the PKCS#11 provider and stores a reference at
   * <code>tokenKeyStore__</code>.
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
   * This method gets the key stores of all inserted (compatible) smart cards and simply takes the
   * first key-entry. From this key entry it takes the private key and the certificate to retrieve
   * the public key from. The key and certificate are stored in the member variables
   * <code>signatureKey_</code> and <code>signerCertificate_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getSignatureKey(String alias) throws GeneralSecurityException, IOException {
    if (alias == null) {
      // we simply take the first keystore, if there are serveral
      Enumeration aliases = tokenKeyStore_.aliases();

      // and we take the first signature (private) key for simplicity
      while (aliases.hasMoreElements()) {
        String keyAlias = aliases.nextElement().toString();
        Key key = tokenKeyStore_.getKey(keyAlias, null);
        if (key instanceof PrivateKey) {
          Certificate[] certificateChain = tokenKeyStore_.getCertificateChain(keyAlias);
          if (certificateChain != null && certificateChain.length > 0) {
            X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
            boolean[] keyUsage = signerCertificate.getKeyUsage();
            if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature
                                                                    // or non-repudiation, but also
                                                                    // accept if none set
              System.out.println("##########");
              System.out.println("The signature key is: " + key);
              System.out.println("##########");
              // get the corresponding certificate for this signature key
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

      if (signatureKey_ == null) {
        System.out
            .println("Found no signature key. Ensure that a valid card is inserted.");
        throw new GeneralSecurityException("found no signature key");
      }
    } else {
      System.out.println("using signature key with alias: " + alias);
      signatureKey_ = (PrivateKey) tokenKeyStore_.getKey(alias, null);
      signerCertificate_ = (X509Certificate) tokenKeyStore_.getCertificate(alias);
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
   * Normally the data would be read from file. The created S/MIME message is sent using the Java
   * Mail API.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If the data file could not be found.
   */
  public void createMessage(String mailcapPath) throws GeneralSecurityException,
      IOException, MessagingException {
    System.out.println("##########");
    System.out.print("Creating and sending S/Mime signed data... ");

    // register content data handlers for S/MIME types
    SMimeSignedDemo.registerMailCapEntries();

    // create some properties and get the default Session
    Properties props = new Properties();
    props.put("mail.smtp.host", smtpServer_);
    props.put("mail.debug", "true");

    Session session = Session.getDefaultInstance(props, null);

    // Create a demo Multipart
    MimeBodyPart mbp1 = new SMimeBodyPart();
    mbp1.setText("This is a Test of the IAIK S/MIME implementation!\n\n");
    // try to test an attachment
    MimeBodyPart attachment = new SMimeBodyPart();
    attachment.setDataHandler(new DataHandler(new FileDataSource(fileToBeSigned_)));
    attachment.setFileName(fileToBeSigned_);
    Multipart mp = new SMimeMultipart();
    mp.addBodyPart(mbp1);
    mp.addBodyPart(attachment);
    DataHandler dataHandler = new DataHandler(mp, mp.getContentType());

    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(sender_));
    msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient_, false));
    msg.setSentDate(new Date());
    msg.setSubject("SMimeSigned Test using IAIK PKCS#11 Provider");

    SignedContent sc = new SignedContent(false);
    sc.setDataHandler(dataHandler);
    sc.setCertificates(new X509Certificate[] { signerCertificate_ });

    try {
      sc.addSigner((RSAPrivateKey) signatureKey_, signerCertificate_);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    msg.setContent(sc, sc.getContentType());

    Transport.send(msg);

    System.out.println("finished");
    System.out.println("##########");
  }

  public static void registerMailCapEntries() {
    MailcapCommandMap mc = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
    mc.addMailcap("multipart/signed;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
    mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=iaik.smime.signed_content");
    mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=iaik.smime.encrypted_content");
    mc.addMailcap("application/x-pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
    mc.addMailcap("application/pkcs10;; x-java-content-handler=iaik.smime.pkcs10_content");
    CommandMap.setDefaultCommandMap(mc);
  }

  /**
   * Print information how to use this demo class.
   */
  public static void printUsage() {
    System.out
        .println("Usage: SMimeSignedDemo <file to sign> <sender> <recipient> <SMTP server> <mailcapFilePath> [<keyAlias>]");
    System.out
        .println(" e.g.: SMimeSignedDemo message.txt karl.scheibelhofer@iaik.tugraz.at karl.scheibelhofer@iaik.tugraz.at smtp.mxcomp.com mailcap MaxMustermann");
  }

}
