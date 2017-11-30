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

import iaik.asn1.DerCoder;
import iaik.asn1.ObjectID;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.DHPrivateKey;
import iaik.pkcs.pkcs11.objects.DHPublicKey;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECDSAPrivateKey;
import iaik.pkcs.pkcs11.objects.ECDSAPublicKey;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RC2SecretKey;
import iaik.pkcs.pkcs11.objects.RC4SecretKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;

public abstract class KeyTemplateDemo {

  public static SecretKey getCipherSecretKeyTemplate(String algorithm) {
    SecretKey secretKeyTemplate = getSecretKeyTemplate(algorithm);
    secretKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    secretKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    return secretKeyTemplate;
  }

  public static SecretKey getSignatureSecretKeyTemplate(String algorithm) {
    SecretKey secretKeyTemplate = getSecretKeyTemplate(algorithm);
    secretKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
    secretKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
    return secretKeyTemplate;
  }

  public static SecretKey getWrappingSecretKeyTemplate(String algorithm) {
    SecretKey secretKeyTemplate = getSecretKeyTemplate(algorithm);
    secretKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
    secretKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
    return secretKeyTemplate;
  }

  public static SecretKey getDerivationSecretKeyTemplate(String algorithm) {
    SecretKey secretKeyTemplate = getSecretKeyTemplate(algorithm);
    secretKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
    return secretKeyTemplate;
  }

  private static SecretKey getSecretKeyTemplate(String algorithm) {
    SecretKey secretKeyTemplate;
    algorithm = algorithm.toLowerCase();
    if (algorithm.equals("aes")) {
      AESSecretKey aesKeyTemplate = new AESSecretKey();
      aesKeyTemplate.getValueLen().setLongValue(new Long(16));
      secretKeyTemplate = aesKeyTemplate;
    } else if (algorithm.equals("des")) {
      secretKeyTemplate = new DESSecretKey();
    } else if (algorithm.equals("2des") || algorithm.equals("des2")
        || algorithm.equals("2-des") || algorithm.equals("des-2")) {
      secretKeyTemplate = new DES2SecretKey();
    } else if (algorithm.equals("3des") || algorithm.equals("des3")
        || algorithm.equals("3-des") || algorithm.equals("des-3")
        || algorithm.equals("tripledes") || algorithm.equals("triple-des")
        || algorithm.equals("desede")) {
      secretKeyTemplate = new DES3SecretKey();
    } else if (algorithm.equals("rc2")) {
      RC2SecretKey tempKey = new RC2SecretKey();
      tempKey.getValueLen().setLongValue(new Long(16));
      secretKeyTemplate = tempKey;
    } else if (algorithm.equals("rc4")) {
      RC4SecretKey tempKey = new RC4SecretKey();
      tempKey.getValueLen().setLongValue(new Long(16));
      secretKeyTemplate = tempKey;
    } else {
      GenericSecretKey genericKeyTemplate = new GenericSecretKey();
      genericKeyTemplate.getValueLen().setLongValue(new Long(16));
      secretKeyTemplate = genericKeyTemplate;
    }

    secretKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // temporary session key
    secretKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE); // only accessible after log-in
    secretKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE); // key should not leave the
                                                                    // token

    return secretKeyTemplate;
  }

  public static PrivateKey getCipherPrivateKeyTemplate(String algorithm) {
    PrivateKey privateKeyTemplate = getPrivateKeyTemplate(algorithm);
    privateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
    return privateKeyTemplate;
  }

  public static PrivateKey getSignaturePrivateKeyTemplate(String algorithm) {
    PrivateKey privateKeyTemplate = getPrivateKeyTemplate(algorithm);
    privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
    return privateKeyTemplate;
  }

  public static PrivateKey getWrappingPrivateKeyTemplate(String algorithm) {
    PrivateKey privateKeyTemplate = getPrivateKeyTemplate(algorithm);
    privateKeyTemplate.getUnwrap().setBooleanValue(Boolean.TRUE);
    return privateKeyTemplate;
  }

  public static PrivateKey getDerivationPrivateKeyTemplate(String algorithm) {
    PrivateKey privateKeyTemplate = getPrivateKeyTemplate(algorithm);
    privateKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
    return privateKeyTemplate;
  }

  private static PrivateKey getPrivateKeyTemplate(String algorithm) {
    PrivateKey privateKeyTemplate;
    algorithm = algorithm.toLowerCase();
    if (algorithm.equals("rsa")) {
      privateKeyTemplate = new RSAPrivateKey();
    } else if (algorithm.equals("ecdsa")) {
      privateKeyTemplate = new ECDSAPrivateKey();
    } else if (algorithm.equals("dh")) {
      privateKeyTemplate = new DHPrivateKey();
    } else if (algorithm.equals("dsa")) {
      privateKeyTemplate = new DSAPrivateKey();
    } else {
      System.out.println("algorithm not included in this demo.");
      return null;
    }
    privateKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // temporary session key
    // privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE); // only accessible after
    // log-in
    // privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE); // key should not leave the
    // token

    return privateKeyTemplate;
  }

  private static PublicKey getPublicKeyTemplate(String algorithm) {
    PublicKey publicKeyTemplate;
    algorithm = algorithm.toLowerCase();
    if (algorithm.equals("rsa")) {
      RSAPublicKey rsaPublicKey = new RSAPublicKey();
      // for modules supporting cryptoki <= 2.11 the public exponent has to be specified
      byte[] publicExponentBytes = { 0x01, 0x00, 0x01 };
      rsaPublicKey.getPublicExponent().setByteArrayValue(publicExponentBytes);
      publicKeyTemplate = rsaPublicKey;
    } else if (algorithm.equals("ecdsa")) {
      ECDSAPublicKey ecdsaKeyTemplate = new ECDSAPublicKey();
      ObjectID eccCurveObjectID = new ObjectID("1.3.132.0.35");
      ecdsaKeyTemplate.getEcdsaParams().setByteArrayValue(
          DerCoder.encode(eccCurveObjectID));
      publicKeyTemplate = ecdsaKeyTemplate;
    } else if (algorithm.equals("dh")) {
      publicKeyTemplate = new DHPublicKey();
    } else if (algorithm.equals("dsa")) {
      publicKeyTemplate = new DSAPublicKey();
    } else {
      System.out.println("algorithm not included in this demo.");
      return null;
    }

    publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // temporary session key

    return publicKeyTemplate;

  }

  public static PublicKey getCipherPublicKeyTemplate(String algorithm) {
    PublicKey publicKeyTemplate = getPublicKeyTemplate(algorithm);
    publicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    return publicKeyTemplate;
  }

  public static PublicKey getSignaturePublicKeyTemplate(String algorithm) {
    PublicKey publicKeyTemplate = getPublicKeyTemplate(algorithm);
    publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
    return publicKeyTemplate;
  }

  public static PublicKey getWrappingPublicKeyTemplate(String algorithm) {
    PublicKey publicKeyTemplate = getPublicKeyTemplate(algorithm);
    publicKeyTemplate.getWrap().setBooleanValue(Boolean.TRUE);
    return publicKeyTemplate;
  }

  public static PublicKey getDerivationPublicKeyTemplate(String algorithm) {
    PublicKey publicKeyTemplate = getPublicKeyTemplate(algorithm);
    publicKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
    return publicKeyTemplate;
  }

}
