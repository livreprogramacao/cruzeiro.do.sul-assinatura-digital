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

import iaik.security.provider.IAIK;
import iaik.xml.crypto.XSecProvider;
import iaik.xml.crypto.XmldsigMore;

import java.io.FileInputStream;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * This is a simple demo to show how to validate an XML Signature using the JSR 105 API. It assumes
 * that the public key or the certificate needed to validate the signature is contained in a
 * KeyValue KeyInfo.
 */
public class ValidateXMLwithCertificate {

  /**
   * Main method of the demo. The document to be validated must be specified as argument.
   * 
   * @param args
   *          document to be validated
   * @throws Exception
   *           in case of any error.
   */
  public static void main(String[] args) throws Exception {

    if (args.length == 0) {
      throw new IllegalArgumentException("synopsis: java Validate document[mandatory]");
    }

    // Register IAIK JCE Provider
    Security.addProvider(new IAIK());

    try {
      // try to register the IAIK ECC provider if availiable on the classpath
      Class ecdsaClass = Class.forName("iaik.security.ecc.provider.ECCProvider");
      Security.addProvider((Provider) ecdsaClass.newInstance());
    } catch (Throwable e) {
      // do nothing
    }

    // Register XML Security Provider
    Security.addProvider(new XSecProvider());

    // Instantiate the document to be validated
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(args[0]));

    // Find Signature element
    NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    if (nl.getLength() == 0) {
      throw new Exception("Cannot find Signature element");
    }

    // Create a DOM XMLSignatureFactory that will be used to unmarshal the
    // document containing the XMLSignature
    XMLSignatureFactory fac = iaik.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM",
        new XSecProvider());

    // Create a DOMValidateContext and specify a KeyValue KeySelector
    // and document context
    DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(),
        nl.item(0));

    // unmarshal the XMLSignature
    XMLSignature signature = fac.unmarshalXMLSignature(valContext);

    // Validate the XMLSignature (generated above)
    boolean coreValidity = signature.validate(valContext);

    // Check core validation status
    if (coreValidity == false) {
      System.err.println("Signature failed core validation");
      boolean sv = signature.getSignatureValue().validate(valContext);
      System.out.println("signature validation status: " + sv);
      // check the validation status of each Reference
      Iterator i = signature.getSignedInfo().getReferences().iterator();
      for (int j = 0; i.hasNext(); j++) {
        boolean refValid = ((Reference) i.next()).validate(valContext);
        System.out.println("ref[" + j + "] validity status: " + refValid);
      }
    } else {
      System.out.println("Signature passed core validation");
    }
  }

  /**
   * Private class that extends KeySelector to retrieve the public key out of the KeyValue element
   * and returns it. NOTE: If the key algorithm doesn't match the signature algorithm, then the
   * public key will be ignored.
   */
  private static class KeyValueKeySelector extends KeySelector {

    /**
     * Select the public key from specified keyInfo that matches the required signature algorithm.
     * 
     * @param keyInfo
     *          keyInfo containg public key information
     * @param purpose
     *          purpose of the wanted key
     * @param method
     *          required signature method
     * @param context
     *          properties affecting XML signature validation
     * 
     * @throws KeySelectorException
     */
    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
        AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {
      if (keyInfo == null) {
        throw new KeySelectorException("Null KeyInfo object!");
      }
      SignatureMethod sm = (SignatureMethod) method;
      List list = keyInfo.getContent();

      for (int i = 0; i < list.size(); i++) {
        XMLStructure xmlStructure = (XMLStructure) list.get(i);
        if (xmlStructure instanceof X509Data) {
          List x509datalist = ((X509Data) xmlStructure).getContent();
          for (int y = 0; y < x509datalist.size(); y++) {
            PublicKey pk = null;
            if (x509datalist.get(y) instanceof X509Certificate) {
              pk = ((X509Certificate) x509datalist.get(y)).getPublicKey();
              // make sure algorithm is compatible with method
              if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                return new SimpleKeySelectorResult(pk);
              }
            }
          }
        }
      }
      throw new KeySelectorException("No KeyValue element found!");
    }

    /**
     * Check whether the algorithm used for the public key creation matches the required signature
     * algorithm.
     * 
     * @param algURI
     *          URI of required signature algorithm
     * @param algName
     *          algorithm used for public key
     */
    static boolean algEquals(String algURI, String algName) {
      if (algName.equalsIgnoreCase("DSA")
          && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
        return true;
      } else if (algName.equalsIgnoreCase("RSA")
          && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
        return true;
      } else if (algName.equalsIgnoreCase("ECDSA")
          && algURI.equalsIgnoreCase(XmldsigMore.SIGNATURE_ECDSA_SHA1)) {
        return true;
      } else {
        // if other algorithms are used add a new else clause
        return false;
      }
    }
  }

  /**
   * Private class containing the public key that was selected with KeyValueKeySelector.select.
   */
  private static class SimpleKeySelectorResult implements KeySelectorResult {
    /**
     * Public key to validate signature
     */
    private PublicKey pk;

    /**
     * Constructor setting the field pk
     * 
     * @param pk
     *          public key to validate signature
     */
    SimpleKeySelectorResult(PublicKey pk) {
      this.pk = pk;
    }

    /**
     * returns the public key to validate the signature
     * 
     * @return public key to validate signature
     */
    public Key getKey() {
      return pk;
    }
  }
}
