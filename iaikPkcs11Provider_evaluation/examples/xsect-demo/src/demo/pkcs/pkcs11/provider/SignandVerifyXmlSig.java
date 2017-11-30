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

import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.xml.crypto.XSecProvider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

/**
 * This demo shows how to create an XML signature with a smart card (or HSM). It uses IAIK XSECT to
 * create the XML signature and the IAIK PKCS#11 provider to access the smart card.
 */
public class SignandVerifyXmlSig {

  /**
   * This is the instance of the PKCS#11 provider. It provides access to the smart card.
   */
  private IAIKPkcs11 pkcs11Provider_;

  /**
   * This is the selected signature key. Usually, it does not contain the actual key material. It is
   * a mere proxy object.
   */
  private PrivateKey signatureKey_;

  /**
   * This is the signing certificate that is associated with the signing key. The demo includes this
   * certificate in the XML signature.
   */
  private X509Certificate signingCertificate_;

  /**
   * This is the resulting XML document that contains the XML signature.
   */
  private Document doc_;

  /**
   * Construct a new demo object using the specified PKCS#11 module.
   * 
   * @param pkcs11module
   *          The name of the PKCS#11 module, e.g. <code>aetpkss1.dll</code>
   */
  private SignandVerifyXmlSig() {

    // install the PKCS#11 provider
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
    // try if we have a ECC provider available, if yes, add it
    try {
      Class eccProviderClass = Class.forName("iaik.security.ec.provider.ECCelerate");
      Provider eccProvider = (Provider) eccProviderClass.newInstance();
      Security.addProvider(eccProvider);
    } catch (Exception e) {
      // ignore, we only need it for ECDSA Keys
    }

    // configure delegation for RSA signature with SHA-1
    XSecProvider
        .setDelegationProvider("Signature.SHA1withRSA", pkcs11Provider_.getName());
    // install IAIK XML Security Provider (XSECT) and IAIK JCE Provider
    XSecProvider.addAsProvider(false, true);
  }

  /**
   * This is the main method. It triggers the different steps of this demo.
   * 
   * @param args
   *          ignored
   * @throws Exception
   *           in case of any error.
   */
  public static void main(String[] args) throws Exception {

    if (args.length < 2) {
      printUsage();
      throw new Exception("missing arguments");
    }

    SignandVerifyXmlSig demo = new SignandVerifyXmlSig();
    demo.selectSignatureKey((args.length < 3) ? null : args[2]);
    demo.createXmlSignature("file:" + args[0]);
    demo.writeResult(args[1]);
    ValidateXMLwithCertificate.main(new String[] { args[1] });

  }

  /**
   * This method gets the first key-entry that is a RSA key with a signature certificate. It stores
   * the key in {@link #signatureKey_} and the certificate in {@link #signingCertificate_}.
   * 
   * @exception GeneralSecurityException
   *              If anything with the key store fails.
   */
  private void selectSignatureKey(String alias) throws GeneralSecurityException {
    KeyStore tokenKeyStore = pkcs11Provider_.getTokenManager().getKeyStore();
    if (alias != null) {
      System.out.println("using signature key with alias: " + alias);
      signatureKey_ = (PrivateKey) tokenKeyStore.getKey(alias, null);
      signingCertificate_ = (X509Certificate) tokenKeyStore.getCertificate(alias);
    } else {
      // we take the first signature (private) key for simplicity
      Enumeration aliases = tokenKeyStore.aliases();
      while (aliases.hasMoreElements()) {
        String keyAlias = aliases.nextElement().toString();
        Key key = tokenKeyStore.getKey(keyAlias, null);
        if (key instanceof RSAPrivateKey) {
          Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
          X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
          boolean[] keyUsage = signerCertificate.getKeyUsage();
          // check for digital signature or non-repudiation,
          // but also accept if none is set
          if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) {
            signatureKey_ = (PrivateKey) key;
            signingCertificate_ = signerCertificate;
            break;
          }
        }
      }
    }

    if (signatureKey_ == null) {
      throw new GeneralSecurityException(
          "Found no signature key. Ensure that a valid card is inserted.");
    }
  }

  /**
   * Create the actual XML signature. This method works like a usual XML signature creation.
   * 
   * @param dataURL
   *          The URL of the signed data.
   * @throws GeneralSecurityException
   *           If any crypto operation fails.
   * @throws ParserConfigurationException
   *           If the DOM-parser is configured incorrectly.
   * @throws MarshalException
   *           If the XML signature cannot be marshaled.
   * @throws XMLSignatureException
   *           If creating the XML signature fails.
   */
  private void createXmlSignature(String dataURL) throws GeneralSecurityException,
      ParserConfigurationException, XMLSignatureException, MarshalException {
    // First, create a DOM XMLSignatureFactory that will be used to
    // generate the XMLSignature and marshal it to DOM.
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    // Create a Reference to an external URI that will be digested
    // using the SHA1 digest algorithm
    Reference ref = fac.newReference(dataURL,
        fac.newDigestMethod(DigestMethod.SHA1, null));

    // Create the SignedInfo
    CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(
        CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null);
    SignatureMethod signatureMethod = fac.newSignatureMethod(SignatureMethod.RSA_SHA1,
        null);
    SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod,
        Collections.nCopies(1, ref));

    // Create a KeyValue containing the DSA PublicKey that was generated
    KeyInfoFactory kif = fac.getKeyInfoFactory();
    X509Data x509data = kif.newX509Data(Collections.nCopies(1, signingCertificate_));

    // Create a KeyInfo and add the KeyValue to it
    KeyInfo ki = kif.newKeyInfo(Collections.nCopies(1, x509data));

    // Create the XMLSignature (but don't sign it yet)
    XMLSignature signature = fac.newXMLSignature(si, ki);

    // Create the Document that will hold the resulting XMLSignature
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true); // must be set
    doc_ = dbf.newDocumentBuilder().newDocument();

    // Create a DOMSignContext and set the signing Key to the RSA
    // PrivateKey and specify where the XMLSignature should be inserted
    // in the target document (in this case, the document root)
    DOMSignContext signContext = new DOMSignContext((Key) signatureKey_, doc_);

    // Marshal, generate (and sign) the detached XMLSignature. The DOM
    // Document will contain the XML Signature if this method returns
    // successfully.
    signature.sign(signContext);
  }

  /**
   * Write to standard out the resulting XML document that contains the XML signature.
   * 
   * @throws TransformerException
   *           If creating a transformer fails.
   * @throws IOException
   *           If writing the document fails.
   */
  private void writeResult(String signedFileName) throws TransformerException,
      IOException {
    // output the resulting document either in file if specified or on screen
    OutputStream os;
    if (signedFileName != null) {
      os = new FileOutputStream(signedFileName);
    } else {
      os = System.out;
    }

    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer trans = tf.newTransformer();
    trans.transform(new DOMSource(doc_), new StreamResult(os));

    System.out.println("Signature created.");

  }

  public static void printUsage() {
    System.out
        .println("Usage: SignedandVerifyXmlSig <fileToBeSigned> <signedFileName> [<keyalias>]");
    System.out
        .println(" e.g.: SignedandVerifyXmlSig toBeSigned.xml toBeValidated.xml MaxMustermann");
  }

}
