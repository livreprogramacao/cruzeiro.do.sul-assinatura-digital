// Copyright (C) 2002 IAIK
// http://jce.iaik.tugraz.at
//
// Copyright (C) 2003 Stiftung Secure Information and 
//                    Communication Technologies SIC
// http://jce.iaik.tugraz.at
//
// All rights reserved.
//
// This source is provided for inspection purposes and recompilation only,
// unless specified differently in a contract with IAIK. This source has to
// be kept in strict confidence and must not be disclosed to any third party
// under any circumstances. Redistribution in source and binary forms, with
// or without modification, are <not> permitted in any case!
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
//
// $Header: /IAIK-CMS/current/src/demo/smime/basic/SMimeDemo.java 46    18.04.16 16:28 Dbratko $
// $Revision: 46 $
//

package demo.smime.basic;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.cms.CMSAlgorithmID;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs10.CertificateRequest;
import iaik.smime.CompressedContent;
import iaik.smime.EncryptedContent;
import iaik.smime.PKCS10Content;
import iaik.smime.SMimeBodyPart;
import iaik.smime.SMimeMultipart;
import iaik.smime.SMimeParameters;
import iaik.smime.SignedContent;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import demo.DemoSMimeUtil;
import demo.DemoUtil;
import demo.keystore.CMSKeyStore;
import demo.smime.DumpMessage;

/**
 * This class demonstrates the usage of the IAIK S/MIME implementation. It shows how to create
 * signed and/or encrypted S/MIME messages and how to parse them and verify the signatures 
 * and decrypt the content, respectively.
 * To run this demo the following packages are required:
 * <ul>
 *    <li>
 *       <code>mail.jar</code>: Get it from <a href="http://www.oracle.com/technetwork/java/javamail/index.html">JavaMail</a>.
 *    </li>   
 *    <li>
 *       <code>activation.jar</code> (required for JDK versions < 1.6): Get it from <a href="http://www.oracle.com/technetwork/java/javase/downloads/index-135046.html">Java Activation Framework</a>.
 *    </li> 
 * </ul>
 *
 * @author Dieter Bratko
 */
public class SMimeDemo {
    
  // whether to print dump all generates test messages to System.out
  final static boolean PRINT_MESSAGES = false;   

  String firstName_ = "John";                     // name of sender
  String lastName_ = "SMime";
  String from_ = "smimetest@iaik.tugraz.at";      // email sender
  String to_ = "smimetest@iaik.tugraz.at";        // email recipient
  String host_ = "mailhost";                      // name of the mailhost

  X509Certificate[] signerCertificates_;          // list of certificates to include in the S/MIME message
  X509Certificate recipientCertificate_;          // certificate of the recipient
  X509Certificate signerCertificate_;             // certificate of the signer/sender
  X509Certificate encryptionCertOfSigner_;        // signer uses different certificate for encryption
  PrivateKey signerPrivateKey_;                   // private key of the signer/sender
  
  /**
   * Default constructor. Reads certificates and keys from the demo keystore.
   */
  public SMimeDemo() {
    
    System.out.println();
    System.out.println("******************************************************************************************");
    System.out.println("*                                 SMimeDemo demo                                         *");
    System.out.println("* (shows how to create and parse (verify, decrypt) signed and encrypted S/MIME messages) *");
    System.out.println("******************************************************************************************");
    System.out.println();
    
    // get the certificates from the KeyStore
    signerCertificates_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerPrivateKey_ = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_SIGN);
    signerCertificate_ = signerCertificates_[0];

    // recipient = signer for this test
    recipientCertificate_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_)[0];
    PrivateKey recipientKey = CMSKeyStore.getPrivateKey(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT_);
    DumpMessage.privateKey = recipientKey;
    encryptionCertOfSigner_ = CMSKeyStore.getCertificateChain(CMSKeyStore.RSA, CMSKeyStore.SZ_1024_CRYPT)[0];
  }
  
  /**
   * Starts the demo.
   *
   * @exception IOException if an I/O related error occurs
   */
  public void start() throws IOException {

  	// get the default Session
  	Session session = DemoSMimeUtil.getSession();

  	try {
      // Create a demo Multipart
      MimeBodyPart mbp1 = new SMimeBodyPart();
      mbp1.setText("This is a Test of the IAIK S/MIME implementation!\n\n");
	  // attachment
      MimeBodyPart attachment = new SMimeBodyPart();
      attachment.setDataHandler(new DataHandler(new FileDataSource("test.html")));
      attachment.setFileName("test.html");
        
      Multipart mp = new SMimeMultipart();
      mp.addBodyPart(mbp1);
      mp.addBodyPart(attachment);
      DataHandler multipart = new DataHandler(mp, mp.getContentType());

      Message msg;    // the message to send
      ByteArrayOutputStream baos = new ByteArrayOutputStream(); // we write to a stream
      ByteArrayInputStream bais;  // we read from a stream

      // 1. This is a plain message
      msg = createPlainMessage(session, multipart);
      System.out.println("creating plain message...");
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

      // 2. This is an explicitly signed message
      msg = createSignedMessage(session, multipart, false);
      System.out.println("creating explicitly signed message...");
      baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");


      // 3. This is an implicitly signed message
      msg = createSignedMessage(session, multipart, true);
      System.out.println("creating implicitly signed message...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

      // 4. Now create encrypted messages with different content encryption algorithms
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.rc2_CBC.clone(), 40);
      System.out.println("creating encrypted message [RC2/40]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");
	  
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.rc2_CBC.clone(), 64);
      System.out.println("creating encrypted message [RC2/64]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");
	  
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.rc2_CBC.clone(), 128);
      System.out.println("creating encrypted message [RC2/128]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");
	  
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.des_EDE3_CBC.clone(), 192);
      System.out.println("creating encrypted message [TripleDES]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
      	  
	  System.out.println("\n\n*****************************************\n\n");
      
      msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.aes128_CBC.clone(), 128);
      System.out.println("creating encrypted message [AES/128]...");
      baos.reset();
      msg.saveChanges();
      msg.writeTo(baos);
      bais = new ByteArrayInputStream(baos.toByteArray());
      msg = new MimeMessage(null, bais);
      if (PRINT_MESSAGES) {
        printMessage(msg);
      }
      DumpMessage.dump(msg);
      
      System.out.println("\n\n*****************************************\n\n");
      
      if (DemoUtil.getIaikProviderVersion() >= 3.14) {
        msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.aes192_CBC.clone(), 192);
        System.out.println("creating encrypted message [AES/192]...");
        baos.reset();
        msg.saveChanges();
        msg.writeTo(baos);
        bais = new ByteArrayInputStream(baos.toByteArray());
        msg = new MimeMessage(null, bais);
        if (PRINT_MESSAGES) {
          printMessage(msg);
        }
        DumpMessage.dump(msg);
        
        System.out.println("\n\n*****************************************\n\n");
        
        msg = createEncryptedMessage(session, (AlgorithmID)AlgorithmID.aes256_CBC.clone(), 256);
        System.out.println("creating encrypted message [AES/256]...");
        baos.reset();
        msg.saveChanges();
        msg.writeTo(baos);
        bais = new ByteArrayInputStream(baos.toByteArray());
        msg = new MimeMessage(null, bais);
        if (PRINT_MESSAGES) {
          printMessage(msg);
        }
        DumpMessage.dump(msg);
        
        System.out.println("\n\n*****************************************\n\n");
      }  


      // 5. Now create a implicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, true);
      System.out.println("creating implicitly signed and encrypted message [RC2/128]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

      // 6. Now create a explicitly signed and encrypted message with attachment
      msg = createSignedAndEncryptedMessage(session, multipart, false);
      System.out.println("creating explicitly signed and encrypted message [RC2/128]...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

	  // 7. certs only message
	  msg = createCertsOnlyMessage(session);
	  System.out.println("creating certs-only message");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

	  // 8. certs only message where the cert list is put into the second part
	  msg = createCertsOnlyMultiPartMessage(session);
	  System.out.println("creating message with certs-only part");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

	  // 9. application/pkcs10 cert request message
      msg = createPKCS10Message(session);
      System.out.println("creating application/pkcs10 message...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

	  // 10. application/pkcs10 message where the request is in the second part
	  msg = createPKCS10MultiPartMessage(session);
	  System.out.println("creating message with pkcs10 part...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);
	  
	  System.out.println("\n\n*****************************************\n\n");

	  // 11. compressed message 
	  msg = createCompressedMessage(session, multipart, (AlgorithmID)CMSAlgorithmID.zlib_compress.clone());
	  System.out.println("creating message with compressed data...");
	  baos.reset();
	  msg.saveChanges();
	  msg.writeTo(baos);
	  bais = new ByteArrayInputStream(baos.toByteArray());
	  msg = new MimeMessage(null, bais);
	  if (PRINT_MESSAGES) {
        printMessage(msg);
      }
	  DumpMessage.dump(msg);

  	} catch (Exception ex) {
	    ex.printStackTrace();
	    throw new RuntimeException(ex.toString());
  	}
  }
  
  /**
   * Creates a MIME message container with the given subject for the given session.
   * 
   * @param session the mail sesion
   * @param subject the subject of the message
   *
   * @return the MIME message with FROM, TO, DATE and SUBJECT headers (without content)
   *
   * @exception MessagingException if the message cannot be created
   */
  public Message createMessage(Session session, String subject) throws MessagingException {
    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(from_));
	msg.setRecipients(Message.RecipientType.TO,	InternetAddress.parse(to_, false));
	msg.setSentDate(new Date());
    msg.setSubject(subject);
    return msg;
  }
  
  /**
   * Creates a simple plain (neither signed nor encrypted) message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message
   * 
   * @return the plain message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createPlainMessage(Session session, DataHandler dataHandler) throws MessagingException {

    Message msg = createMessage(session, "IAIK-S/MIME: Plain message");
    if (dataHandler != null) {
      msg.setDataHandler(dataHandler);
    } else {
      msg.setText("This is a plain message!\nIt is wether signed nor encrypted!\n");
    }
	return msg;
  }
  
  /**
   * Creates a signed and encrypted message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed and encrypted
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * 
   * @return the signed and encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedAndEncryptedMessage(Session session, DataHandler dataHandler, boolean implicit)
    throws MessagingException {

    String subject = null;
    String text = null;
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed and Encrypted";
      text = "This message is implicitly signed and encrypted!\n\n\n";
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed and Encrypted";
      text = "This message is explicitly signed and encrypted!\n\n\n";
    }
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(implicit);
    if (dataHandler != null) {
      sc.setDataHandler(dataHandler);
    } else {
      sc.setText(text);
    }
    sc.setCertificates(signerCertificates_);
    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    EncryptedContent ec = new EncryptedContent(sc);
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // set the encryption algorithm
    try {
      ec.setEncryptionAlgorithm((AlgorithmID)AlgorithmID.rc2_CBC.clone(), 128);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   
    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

    return msg;
  }
  
  /**
   * Creates a signed message.
   *
   * @param session the mail session
   * @param dataHandler the content of the message to be signed
   * @param implicit whether to use implicit (application/pkcs7-mime) or explicit
   *                 (multipart/signed) signing
   * 
   * @return the signed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createSignedMessage(Session session, DataHandler dataHandler, boolean implicit)
      throws MessagingException {

    String subject = null;
    StringBuffer buf = new StringBuffer();
    
    if (implicit) {
      subject = "IAIK-S/MIME: Implicitly Signed";
      buf.append("This message is implicitly signed!\n");
      buf.append("You need an S/MIME aware mail client to view this message.\n");
      buf.append("\n\n");
    } else {
      subject = "IAIK-S/MIME: Explicitly Signed";
      buf.append("This message is explicitly signed!\n");
      buf.append("Every mail client can view this message.\n");
      buf.append("Non S/MIME mail clients will show the signature as attachment.\n");
      buf.append("\n\n");
    }
    
    Message msg = createMessage(session, subject);

    SignedContent sc = new SignedContent(implicit);

    if (dataHandler != null) {
      sc.setDataHandler(dataHandler);
    } else {
      sc.setText(buf.toString());
    }
    sc.setCertificates(signerCertificates_);

    try {
      sc.addSigner((RSAPrivateKey)signerPrivateKey_, signerCertificate_);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Algorithm not supported: " + ex.getMessage(), ex);
    }

    msg.setContent(sc, sc.getContentType());
    // let the SignedContent update some message headers
    sc.setHeaders(msg);
    return msg;
  }
  
  /**
   * Creates an encrypted message.
   *
   * @param session the mail session
   * @param algorithm the content encryption algorithm to be used
   * @param keyLength the length of the secret content encryption key to be created and used
   * 
   * @return the encrypted message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createEncryptedMessage(Session session, AlgorithmID algorithm, int keyLength)
      throws MessagingException {

    StringBuffer subject = new StringBuffer();
    subject.append("IAIK-S/MIME: Encrypted ["+algorithm.getName());
    if (keyLength > 0) {
      subject.append("/"+keyLength);
    }  
    subject.append("]");
    Message msg = createMessage(session, subject.toString());

    EncryptedContent ec = new EncryptedContent();

    StringBuffer buf = new StringBuffer();
    buf.append("This is the encrypted content!\n");
    buf.append("Content encryption algorithm: "+algorithm.getName());
    buf.append("\n\n");

    ec.setText(buf.toString());
    // encrypt for the recipient
    ec.addRecipient(recipientCertificate_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    // I want to be able to decrypt the message, too
    ec.addRecipient(encryptionCertOfSigner_, (AlgorithmID)AlgorithmID.rsaEncryption.clone());
    try {
      ec.setEncryptionAlgorithm(algorithm, keyLength);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Content encryption algorithm not supported: " + ex.getMessage());   
    }   

    msg.setContent(ec, ec.getContentType());
    // let the EncryptedContent update some message headers
    ec.setHeaders(msg);

    return msg;
  }
  
  /**
   * Creates a certs-only message.
   *
   * @param session the mail session
   * 
   * @return the certs-only message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCertsOnlyMessage(Session session)
      throws MessagingException {

    Message msg = createMessage(session, "IAIK S/MIME: Certs-only message");
    //use new content types
    SMimeParameters.useNewContentTypes(true);
    SignedContent sc = new SignedContent(true, SignedContent.CERTS_ONLY);
    sc.setCertificates(signerCertificates_);
    msg.setContent(sc, sc.getContentType());
    //set filename and attachment parameters
    sc.setHeaders(msg);


    return msg;
  }
  
  /**
   * Creates a certs-only message where the certificate list is transferred as attachment.
   *
   * @param session the mail session
   * 
   * @return the certs-only message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCertsOnlyMultiPartMessage(Session session) throws MessagingException {

    MimeBodyPart mbp1 = new MimeBodyPart();
	mbp1.setText("This is a test where the certs-only message is included in the second part!\n\n");

    MimeBodyPart attachment = new MimeBodyPart();
    //use new content types
    SMimeParameters.useNewContentTypes(true);
    SignedContent sc = new SignedContent(true, SignedContent.CERTS_ONLY);
    sc.setCertificates(signerCertificates_);
    attachment.setContent(sc, sc.getContentType());
    // let the SignedContent update some headers
    sc.setHeaders(attachment);
    Multipart mp = new MimeMultipart();
    mp.addBodyPart(mbp1);
    mp.addBodyPart(attachment);

    Message msg = createMessage(session, "IAIK S/MIME: Certs-only multipart message");
    msg.setContent(mp, mp.getContentType());

    return msg;
  }
  
  /**
   * Creates a compressed message.
   *
   * @param session the mail session
   * @param dataHandler the datahandler supplying the content to be compressed
   * @param algorithm the compression algorithm to be used
   * 
   * @return the compressed message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createCompressedMessage(Session session, DataHandler dataHandler, AlgorithmID algorithm)
      throws MessagingException {

    String subject = "IAIK-S/MIME: Compressed ["+algorithm.getName()+"]";
    Message msg = createMessage(session, subject.toString());

    CompressedContent compressedContent = new CompressedContent();
    
    if (dataHandler == null) {
      StringBuffer buf = new StringBuffer();
      buf.append("This is the compressed content!\n");
      buf.append("Compression algorithm: "+algorithm.getName());
      buf.append("\n\n");
      compressedContent.setText(buf.toString());
    } else {
      compressedContent.setDataHandler(dataHandler);   
    }    
    
    try {
      compressedContent.setCompressionAlgorithm(algorithm);
    } catch (NoSuchAlgorithmException ex) {
      throw new MessagingException("Compression algorithm not supported: " + ex.getMessage());   
    }   

    msg.setContent(compressedContent, compressedContent.getContentType());
    // let the CompressedContent update some message headers
    compressedContent.setHeaders(msg);

    return msg;
  }
  
  /**
   * Creates a PKCS#10 certificate request message.
   *
   * @param session the mail session
   * 
   * @return the PKCS#10 certificate request message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createPKCS10Message(Session session)
    throws MessagingException {

    Message msg = createMessage(session, "IAIK-S/MIME: Certificate Request");

    PKCS10Content pc = new PKCS10Content();
    CertificateRequest request = null;
    try {
       request = createCertificateRequest();
    } catch (PKCSException ex) {
       throw new MessagingException(ex.getMessage());
    }
    pc.setCertRequest(request);
    msg.setContent(pc, pc.getContentType());
    // let the PKCS10Content update some message headers
    pc.setHeaders(msg);

    return msg;
  }
  
    /**
   * Creates a PKCS#10 message where the certificate request is transferred as attachment.
   *
   * @param session the mail session
   * 
   * @return the PKCS#10 certificate request message
   *
   * @exception MessagingException if an error occurs when creating the message
   */
  public Message createPKCS10MultiPartMessage(Session session) throws MessagingException {

    MimeBodyPart mbp1 = new MimeBodyPart();
	mbp1.setText("This is a test where the request message is included in the second part!\n\n");
	// try to test an attachment
	// this demo attaches our homepage
    MimeBodyPart attachment = new MimeBodyPart();
    //use new content types
    SMimeParameters.useNewContentTypes(true);
    PKCS10Content pc = new PKCS10Content();
    CertificateRequest request = null;
    try {
       request = createCertificateRequest();
    } catch (PKCSException ex) {
       throw new MessagingException(ex.getMessage());
    }
    pc.setCertRequest(request);
    DataHandler pkcs10Handler = new DataHandler(pc, pc.getContentType());
    attachment.setDataHandler(pkcs10Handler);
    attachment.setDisposition("attachment");
    attachment.setFileName("smime.p10");
    Multipart mp = new MimeMultipart();
    mp.addBodyPart(mbp1);
    mp.addBodyPart(attachment);

    Message msg = createMessage(session, "IAIK-S/MIME: Certificate Request multipart message");
    msg.setContent(mp, mp.getContentType());
    return msg;
  }
  
  /**
   * Creates a PKCS#10 certificate request.
   *
   * @return the certificate request
   *
   * @exception PKCSException if the request cannot be created
   */
  private CertificateRequest createCertificateRequest() throws PKCSException {
    try {
      Name subject = new Name();
	  subject.addRDN(ObjectID.commonName, firstName_ + " " + lastName_);
	  subject.addRDN(ObjectID.emailAddress, from_);
	  CertificateRequest certRequest;

      certRequest = new CertificateRequest(signerCertificate_.getPublicKey(), subject);
  	  certRequest.sign((AlgorithmID)AlgorithmID.sha1WithRSAEncryption.clone(), signerPrivateKey_);
  	  certRequest.verify();
  	  return certRequest;
  	} catch (Exception ex) {
  	  throw new PKCSException("Cannot create cert request: " + ex.getMessage());
  	}
  }
  
  
  /** 
   * Prints a dump of the given message to System.out.
   *
   * @param msg the message to be dumped to System.out
   */
  static void printMessage(Message msg) throws IOException {
    System.out.println("------------------------------------------------------------------");
    System.out.println("Message dump: \n");
    try {
      msg.writeTo(System.out);
    } catch (MessagingException ex) {
      throw new IOException(ex.getMessage());   
    }    
    System.out.println("\n------------------------------------------------------------------");
  }  


  /**
   * The main method.
   */
  public static void main(String[] argv) throws IOException {

    DemoSMimeUtil.initDemos();
   	(new SMimeDemo()).start();
    System.out.println("\nReady!");
    DemoUtil.waitKey();
  }
}
