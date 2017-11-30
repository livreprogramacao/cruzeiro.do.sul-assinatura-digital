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

//class and interface imports
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Version;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keygenerators.PKCS11KeyGenerationSpec;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.security.GeneralSecurityException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import demo.pkcs.pkcs11.provider.utils.DemoUtils;
import demo.pkcs.pkcs11.provider.utils.KeyTemplateDemo;

/**
 * This class shows a short demonstration of how to use this provider implementation for a secret
 * key generation.
 */
public class SecretKeyGenerationDemo {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The new key-pair.
   */
  protected SecretKey secretKey_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public SecretKeyGenerationDemo() {
    DemoUtils.addSoftwareProvider();
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_);
  }

  public static void main(String[] args) throws GeneralSecurityException {
    SecretKeyGenerationDemo demo = new SecretKeyGenerationDemo();

    String algorithm = (args.length > 0) ? args[0] : "AES"; // specify the required symmetric
                                                            // algorithm, e.g. AES, DES, DESede...
    demo.generateSecretKeySimple(algorithm);
    demo.generateSecretKeyMultipleProvider(algorithm);
    demo.generateSecretKeyDetailed(algorithm);
    demo.printKeyPair(algorithm);

    System.out.flush();
    System.err.flush();
  }

  /**
   * This method generates a secret key on a simple and not flexible way. On some tokens this method
   * creates permanent keys although not needed or the other way round (the default settings of the
   * token are used). It stores the secret key in the member variable <code>secretKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateSecretKeySimple(String algorithm) throws GeneralSecurityException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());
    secretKey_ = keyGenerator.generateKey();
  }

  /**
   * This method generates a secret key for a specific instance of IAIK PKCS#11 provider, if
   * multiple instances are used in parallel. On some tokens this method creates permanent keys
   * although not needed or the other way round (the default settings of the token are used). It
   * stores the secret key in the member variable <code>secretKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateSecretKeyMultipleProvider(String algorithm)
      throws GeneralSecurityException {
    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());
    // get a default template
    iaik.pkcs.pkcs11.objects.SecretKey keyTemplate = IAIKPkcs11.getGlobalKeyHandler()
        .getKeyGeneratorTemplate(algorithm, -1);
    PKCS11KeyGenerationSpec pkcs11AlgParamSepc = (PKCS11KeyGenerationSpec) new PKCS11KeyGenerationSpec(
        keyTemplate).setUseUserRole(false);
    keyGenerator.init(pkcs11AlgParamSepc);
    secretKey_ = keyGenerator.generateKey();
  }

  /**
   * This method generates a secret key by specifying the required attributes. It stores the secret
   * key in the member variable <code>secretKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void generateSecretKeyDetailed(String algorithm) throws GeneralSecurityException {
    System.out.print("Generating a " + algorithm + " key-pair...");

    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());

    iaik.pkcs.pkcs11.objects.SecretKey secretKeyTemplate = KeyTemplateDemo
        .getCipherSecretKeyTemplate(algorithm);

    // additionally a label can be set for the key
    secretKeyTemplate.getLabel().setCharArrayValue("demoSecretKey".toCharArray());

    // since PKCS#11 standard version 2.20 you can use these attributes
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
        secretKeyTemplate.getWrapTemplate().setAttributeArrayValue(wrapTemplate);
        secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);

        // example for AES
        if (algorithm.equalsIgnoreCase("AES")) {
          Mechanism[] allowedMechanisms = new Mechanism[2];
          Mechanism mechanism1 = new Mechanism(PKCS11Constants.CKM_AES_CBC);
          allowedMechanisms[0] = mechanism1;
          Mechanism mechanism2 = new Mechanism(PKCS11Constants.CKM_AES_ECB);
          allowedMechanisms[1] = mechanism2;
          // the key can only be used with the specified mechanisms (example for RSA)
          secretKeyTemplate.getAllowedMechanisms().setMechanismAttributeArrayValue(
              allowedMechanisms);
        }
      }
    } catch (TokenException te) {
      // ignore
    }

    PKCS11KeyGenerationSpec keyGenerationSpec = (PKCS11KeyGenerationSpec) new PKCS11KeyGenerationSpec(
        secretKeyTemplate).setUseUserRole(false);

    keyGenerator.init(keyGenerationSpec);

    secretKey_ = keyGenerator.generateKey();

    System.out.println(" finished");
  }

  /**
   * This method prints the generated RSA key-pair (<code>keyPair_</code>).
   */
  public void printKeyPair(String algorithm) {
    System.out
        .println("################################################################################");
    System.out.println("The generated " + algorithm + " key-pair is:");
    if (secretKey_ == null) {
      System.out.println("null");
    } else {
      System.out
          .println("________________________________________________________________________________");
      System.out.println("Secret key:");
      System.out.println(secretKey_);
    }
    System.out
        .println("################################################################################");
  }

}
