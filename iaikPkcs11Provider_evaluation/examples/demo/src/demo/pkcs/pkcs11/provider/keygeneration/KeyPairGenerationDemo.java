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

package demo.pkcs.pkcs11.provider.keygeneration;

// class and interface imports
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Version;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keypairgenerators.PKCS11KeyPairGenerationSpec;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

import javax.crypto.spec.DHParameterSpec;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyTemplateDemo;

/**
 * This class shows a short demonstration of how to use this provider implementation for a key-pair
 * generation.
 */
public class KeyPairGenerationDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The new key-pair.
   */
  protected KeyPair keyPair_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public KeyPairGenerationDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException {
    KeyPairGenerationDemo demo = new KeyPairGenerationDemo();

    String algorithm = (args.length > 0) ? args[0] : "RSA"; // specify the required asymmetric
                                                            // algorithm, e.g. DSA, ECDSA, ...

    demo.generateKeyPairSimple(algorithm);
    demo.generateKeyPairMultipleProvider(algorithm);
    demo.generateKeyPairDetailed(algorithm);
    demo.printKeyPair(algorithm);

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a key-pair on a simple and not flexible way. On some tokens this method
   * creates permanent keys although not needed or the other way round (the default settings of the
   * token are used). It stores the key-pair in the member variable <code>keyPair_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateKeyPairSimple(String algorithm) throws GeneralSecurityException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());
    keyPair_ = keyPairGenerator.generateKeyPair();

  }

  /**
   * This method generates a key-pair for a specific instance of IAIK PKCS#11 provider, if multiple
   * instances are used in parallel. On some tokens this method creates permanent keys although not
   * needed or the other way round (the default settings of the token are used). It stores the
   * key-pair in the member variable <code>keyPair_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateKeyPairMultipleProvider(String algorithm)
      throws GeneralSecurityException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());
    // get a default template
    iaik.pkcs.pkcs11.objects.KeyPair template = IAIKPkcs11.getGlobalKeyHandler()
        .getKeyPairGeneratorTemplate(algorithm, -1);
    keyPairGenerator
        .initialize((PKCS11KeyPairGenerationSpec) new PKCS11KeyPairGenerationSpec(
            template.getPublicKey(), template.getPrivateKey()).setUseUserRole(true));
    keyPair_ = keyPairGenerator.generateKeyPair();

  }

  /**
   * This method generates a key-pair by specifying the required attributes. It stores the key-pair
   * in the member variable <code>keyPair_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateKeyPairDetailed(String algorithm) throws GeneralSecurityException {
    // get private key template with attributes sign, private and sensitive set to true and
    // attribute token set to false
    PrivateKey privateKeyTemplate = KeyTemplateDemo
        .getSignaturePrivateKeyTemplate(algorithm);
    // get public key template with attribute verify set to true and attribute token set to false
    PublicKey publicKeyTemplate = KeyTemplateDemo
        .getSignaturePublicKeyTemplate(algorithm);
    // additionally a label can be set for the keys
    privateKeyTemplate.getLabel().setCharArrayValue("demoPrivateKey".toCharArray());
    publicKeyTemplate.getLabel().setCharArrayValue("demoPublicKey".toCharArray());

    // since PKCS#11 standard version 2.20 you can use these attributes
    // example for RSA
    if (algorithm.equalsIgnoreCase("RSA")) {
      try {
        Version cryptokiVersion = IAIKPkcs11.getModule().getInfo().getCryptokiVersion();
        if ((cryptokiVersion.getMajor() >= 2) && (cryptokiVersion.getMinor() >= 20)) {
          GenericTemplate wrapTemplate = new GenericTemplate();
          BooleanAttribute encrypt = new BooleanAttribute(Attribute.ENCRYPT);
          encrypt.setBooleanValue(Boolean.TRUE);
          wrapTemplate.addAttribute(encrypt);
          BooleanAttribute decrypt = new BooleanAttribute(Attribute.DECRYPT);
          decrypt.setBooleanValue(Boolean.TRUE);
          wrapTemplate.addAttribute(decrypt);
          // only keys matching the template can be wrapped
          publicKeyTemplate.getWrapTemplate().setAttributeArrayValue(wrapTemplate);
          publicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);

          Mechanism[] allowedMechanisms = new Mechanism[2];
          Mechanism mechanism1 = new Mechanism(PKCS11Constants.CKM_RSA_PKCS);
          allowedMechanisms[0] = mechanism1;
          Mechanism mechanism2 = new Mechanism(PKCS11Constants.CKM_SHA1_RSA_PKCS);
          allowedMechanisms[1] = mechanism2;
          // the key can only be used with the specified mechanisms (example for RSA)
          publicKeyTemplate.getAllowedMechanisms().setMechanismAttributeArrayValue(
              allowedMechanisms);
        }
      } catch (TokenException te) {
        // ignore
      }
    }

    AlgorithmParameterSpec keyPairGenerationSpec;
    if (algorithm.equalsIgnoreCase("DSA")) {
      AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator
          .getInstance("DSA", "IAIK");
      parameterGenerator.init(1024);
      AlgorithmParameters parameters = parameterGenerator.generateParameters();
      DSAParameterSpec parameterSpec = (DSAParameterSpec) parameters
          .getParameterSpec(DSAParameterSpec.class);

      keyPairGenerationSpec = (AlgorithmParameterSpec) new PKCS11KeyPairGenerationSpec(
          parameterSpec, publicKeyTemplate, privateKeyTemplate).setUseUserRole(false);
    } else if (algorithm.equalsIgnoreCase("DH")) {
      // for DH a derivation key template is needed
      privateKeyTemplate.getSign().setPresent(false);
      publicKeyTemplate.getVerify().setPresent(false);
      privateKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
      publicKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);

      BigInteger p = new BigInteger(
          "12589626212164087648142963156054693968143531724127210882720574876034885248674417543636718639332350307931351997411747275642172788678286702755019900752157141");
      BigInteger g = new BigInteger(
          "798714029407796779983910943217886294189424826995758502398002980609131374451706837327391684051692474365177068254749526220588451409333567287210386365320453");
      AlgorithmParameterSpec parameterSpec = new DHParameterSpec(p, g);
      keyPairGenerationSpec = (AlgorithmParameterSpec) new PKCS11KeyPairGenerationSpec(
          parameterSpec, publicKeyTemplate, privateKeyTemplate).setUseUserRole(false);
    } else {
      // for RSA key length has to be specified
      if (algorithm.equalsIgnoreCase("RSA")) {
        ((RSAPublicKey) publicKeyTemplate).getModulusBits().setLongValue(new Long(1024));
      }
      keyPairGenerationSpec = (AlgorithmParameterSpec) new PKCS11KeyPairGenerationSpec(
          publicKeyTemplate, privateKeyTemplate).setUseUserRole(false);
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());

    keyPairGenerator.initialize(keyPairGenerationSpec);

    keyPair_ = keyPairGenerator.generateKeyPair();

    System.out.println(" finished");
  }

  /**
   * This method prints the generated key-pair (<code>keyPair_</code>).
   */
  public void printKeyPair(String algorithm) {
    System.out
        .println("################################################################################");
    System.out.println("The generated " + algorithm + " key-pair is:");
    if (keyPair_ == null) {
      System.out.println("null");
    } else {
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Public key:");
      System.out.println(keyPair_.getPublic());
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Private key:");
      System.out.println(keyPair_.getPrivate());
    }
    System.out
        .println("################################################################################");
  }

}
