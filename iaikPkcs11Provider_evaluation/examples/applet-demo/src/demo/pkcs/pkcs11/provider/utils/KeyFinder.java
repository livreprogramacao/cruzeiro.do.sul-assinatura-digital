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

import iaik.asn1.CodingException;
import iaik.pkcs.pkcs11.objects.Key.KeyType;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.pkcs.pkcs11.provider.keygenerators.PKCS11KeyGenerationSpec;
import iaik.pkcs.pkcs11.provider.keypairgenerators.PKCS11KeyPairGenerationSpec;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11SecretKey;
import iaik.utils.KeyAndCertificate;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.util.Enumeration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import demo.pkcs.pkcs11.provider.CreateKeystoreEntryDemo;

public abstract class KeyFinder {

  public static KeyPair findCipherKeyPair(IAIKPkcs11 pkcs11Provider_, String algorithm)
      throws KeyException, GeneralSecurityException, IOException {
    KeyEntryWithAlias keyentry = findKeyPair(pkcs11Provider_, algorithm, "cipher");
    KeyAndCertificate keycert = keyentry.getKeycert();
    return new KeyPair(keycert.getCertificateChain()[0].getPublicKey(),
        keycert.getPrivateKey());
  }

  public static KeyPair findSignatureKeyPair(IAIKPkcs11 pkcs11Provider_, String algorithm)
      throws KeyException, GeneralSecurityException, IOException {
    KeyEntryWithAlias keyentry = findKeyPair(pkcs11Provider_, algorithm, "signature");
    KeyAndCertificate keycert = keyentry.getKeycert();
    return new KeyPair(keycert.getCertificateChain()[0].getPublicKey(),
        keycert.getPrivateKey());
  }

  public static KeyPair findWrappingKeyPair(IAIKPkcs11 pkcs11Provider_, String algorithm)
      throws KeyException, GeneralSecurityException, IOException {
    KeyEntryWithAlias keyentry = findKeyPair(pkcs11Provider_, algorithm, "wrapping");
    KeyAndCertificate keycert = keyentry.getKeycert();
    return new KeyPair(keycert.getCertificateChain()[0].getPublicKey(),
        keycert.getPrivateKey());
  }

  public static KeyPair findDerivationKeyPair(IAIKPkcs11 pkcs11Provider_, String algorithm)
      throws KeyException, GeneralSecurityException, IOException {
    KeyEntryWithAlias keyentry = findKeyPair(pkcs11Provider_, algorithm, "derivation");
    KeyAndCertificate keycert = keyentry.getKeycert();
    return new KeyPair(keycert.getCertificateChain()[0].getPublicKey(),
        keycert.getPrivateKey());
  }

  public static KeyEntryWithAlias findCipherKeyCertificate(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws KeyException, GeneralSecurityException, IOException {
    return findKeyPair(pkcs11Provider_, algorithm, "cipher");
  }

  public static KeyEntryWithAlias findSignatureKeyCertificate(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws KeyException, GeneralSecurityException, IOException {
    return findKeyPair(pkcs11Provider_, algorithm, "signature");
  }

  public static KeyEntryWithAlias findWrappingKeyCertificate(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws KeyException, GeneralSecurityException, IOException {
    return findKeyPair(pkcs11Provider_, algorithm, "wrapping");
  }

  public static KeyEntryWithAlias findDerivationKeyCertificate(
      IAIKPkcs11 pkcs11Provider_, String algorithm) throws KeyException,
      GeneralSecurityException, IOException {
    return findKeyPair(pkcs11Provider_, algorithm, "derivation");
  }

  private static KeyEntryWithAlias findKeyPair(IAIKPkcs11 pkcs11Provider_,
      String algorithm, String usage) throws KeyException, GeneralSecurityException,
      IOException {
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11SingleTokenKeyStore",
        pkcs11Provider_.getName());
    ByteArrayInputStream providerNameInpustStream = new ByteArrayInputStream(
        pkcs11Provider_.getName().getBytes("UTF-8"));

    // load the keystore of the PKCS#11 provider given via input stream
    tokenKeyStore.load(providerNameInpustStream, null);

    Enumeration aliases = tokenKeyStore.aliases();

    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = tokenKeyStore.getKey(keyAlias, null);
      if (key instanceof PrivateKey) {
        iaik.pkcs.pkcs11.objects.PrivateKey wrapperKey = (iaik.pkcs.pkcs11.objects.PrivateKey) ((IAIKPKCS11PrivateKey) key)
            .getKeyObject();
        boolean match = true;

        // check key attributes
        if (!wrapperKey.getKeyType().getLongValue().equals(findKeyType(algorithm))) {
          match = false;
        } else if (usage.equalsIgnoreCase("cipher")
            && !wrapperKey.getDecrypt().getBooleanValue().booleanValue()) {
          match = false;
        } else if (usage.equalsIgnoreCase("signature")
            && !wrapperKey.getSign().getBooleanValue().booleanValue()) {
          match = false;
        } else if (usage.equalsIgnoreCase("wrapping")
            && !wrapperKey.getUnwrap().getBooleanValue().booleanValue()) {
          match = false;
        } else if (usage.equalsIgnoreCase("derivation")
            && !wrapperKey.getDerive().getBooleanValue().booleanValue()) {
          match = false;
        }

        if (!match) {
          continue;
        }

        // checking key usage specified in certificate
        Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
        if (certificateChain.length != 0) {
          X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
          boolean[] keyUsage = signerCertificate.getKeyUsage();
          // check key usage - if none set everything is allowed
          if (keyUsage != null) {
            // check for digital signature or non-repudiation
            if (usage.equalsIgnoreCase("signature") && !keyUsage[0] && !keyUsage[1]) {
              match = false;
            }
            // check for dataEnchipherment
            else if (usage.equalsIgnoreCase("cipher") && !keyUsage[3]) {
              match = false;
            }
            // check for keyEnchipherment
            else if (usage.equalsIgnoreCase("wrapping") && !keyUsage[2]) {
              match = false;
            }
            // check for keyAgreement
            else if (usage.equalsIgnoreCase("derivation") && !keyUsage[4]) {
              match = false;
            }

            if (!match) {
              continue;
            }

          }
          return new KeyEntryWithAlias(new KeyAndCertificate((PrivateKey) key,
              new X509Certificate[] { signerCertificate }), keyAlias);
        }
      }
    }

    // generate new key if no key was found yet
    System.out.println("No suitable key pair found");
    throw new KeyException("No suitable key pair found");
  }

  public static KeyPair generateCipherKeyPair(IAIKPkcs11 pkcs11Provider_, String algorithm)
      throws GeneralSecurityException {
    return generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getCipherPrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getCipherPublicKeyTemplate(algorithm));
  }

  public static KeyPair generateSignatureKeyPair(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getSignaturePrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getSignaturePublicKeyTemplate(algorithm));
  }

  public static KeyPair generateWrappingKeyPair(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getWrappingPrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getWrappingPublicKeyTemplate(algorithm));
  }

  public static KeyPair generateDerivationKeyPair(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getDerivationPrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getDerivationPublicKeyTemplate(algorithm));
  }

  public static KeyEntryWithAlias generateCipherKeyCertificate(
      IAIKPkcs11 pkcs11Provider_, String algorithm) throws GeneralSecurityException,
      CodingException {
    KeyPair keyPair = generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getCipherPrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getCipherPublicKeyTemplate(algorithm));
    CreateKeystoreEntryDemo entryDemo = new CreateKeystoreEntryDemo();
    String label = entryDemo.findUniqueLabel(algorithm);
    // ca key for signing the certificate
    KeyPair caKeyPair = generateSignatureKeyPair(pkcs11Provider_, algorithm);
    KeyAndCertificate keycert = entryDemo.addKeyEntrywithCertificate(label, algorithm,
        keyPair, caKeyPair.getPrivate(), CreateKeystoreEntryDemo.CIPHER);
    return new KeyEntryWithAlias(keycert, label);
  }

  public static KeyEntryWithAlias generateSignatureKeyCertificate(
      IAIKPkcs11 pkcs11Provider_, String algorithm) throws GeneralSecurityException,
      CodingException {
    KeyPair keyPair = generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getSignaturePrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getSignaturePublicKeyTemplate(algorithm));
    CreateKeystoreEntryDemo entryDemo = new CreateKeystoreEntryDemo();
    String label = entryDemo.findUniqueLabel(algorithm);
    KeyAndCertificate keycert = entryDemo.addKeyEntrywithCertificate(label, algorithm,
        keyPair, keyPair.getPrivate(), CreateKeystoreEntryDemo.SIGNATURE);
    return new KeyEntryWithAlias(keycert, label);
  }

  public static KeyEntryWithAlias generateWrappingKeyCertificate(
      IAIKPkcs11 pkcs11Provider_, String algorithm) throws GeneralSecurityException,
      CodingException {
    KeyPair keyPair = generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getWrappingPrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getWrappingPublicKeyTemplate(algorithm));
    CreateKeystoreEntryDemo entryDemo = new CreateKeystoreEntryDemo();
    String label = entryDemo.findUniqueLabel(algorithm);
    // ca key for signing the certificate
    KeyPair caKeyPair = generateSignatureKeyPair(pkcs11Provider_, algorithm);
    KeyAndCertificate keycert = entryDemo.addKeyEntrywithCertificate(label, algorithm,
        keyPair, caKeyPair.getPrivate(), CreateKeystoreEntryDemo.WRAPPING);
    return new KeyEntryWithAlias(keycert, label);
  }

  public static KeyEntryWithAlias generateDerivationKeyCertificate(
      IAIKPkcs11 pkcs11Provider_, String algorithm) throws GeneralSecurityException,
      CodingException {
    KeyPair keyPair = generateKeyPair(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getDerivationPrivateKeyTemplate(algorithm),
        KeyTemplateDemo.getDerivationPublicKeyTemplate(algorithm));
    CreateKeystoreEntryDemo entryDemo = new CreateKeystoreEntryDemo();
    String label = entryDemo.findUniqueLabel(algorithm);
    // ca key for signing the certificate
    KeyPair caKeyPair = generateSignatureKeyPair(pkcs11Provider_, algorithm);
    KeyAndCertificate keycert = entryDemo.addKeyEntrywithCertificate(label, algorithm,
        keyPair, caKeyPair.getPrivate(), CreateKeystoreEntryDemo.DERIVATION);
    return new KeyEntryWithAlias(keycert, label);
  }

  public static KeyPair generateKeyPair(IAIKPkcs11 pkcs11Provider_, String algorithm,
      iaik.pkcs.pkcs11.objects.PrivateKey privateKeyTemplate,
      iaik.pkcs.pkcs11.objects.PublicKey publicKeyTemplate)
      throws GeneralSecurityException {

    TokenManager tokenManager = pkcs11Provider_.getTokenManager();
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());

    AlgorithmParameterSpec keyPairGenerationSpec;
    AlgorithmParameterSpec parameterSpec = null;
    // for DSA DSA Parameter have to be specified
    if (algorithm.equalsIgnoreCase("DSA")) {
      BigInteger p = new BigInteger(
          "128392683547290457889669057385888857728097896474982533012286997145303748175084305080730390117692712377131554101682550943753076962684303573612712821326266204210238140292819244852130733090595068112884131447660790182547424320806552771950994481917330886099386227867078554836003577347392247355674672657895010153463");
      BigInteger q = new BigInteger("1012407340671132343468126301212672316148090104909");
      BigInteger g = new BigInteger(
          "103866450431846492768351497526313808936081567637938485140161582291890693426720625107293705328227706541562568610666395593896156271918103039271279316868868447526610503292016356988341952278386414967774993565287173464905026115665839524723376426172983125206717807693117178202510926922775597710684952068270792684492");
      parameterSpec = new DSAParameterSpec(p, q, g);
    } else if (algorithm.equalsIgnoreCase("DH")) {
      BigInteger p = new BigInteger(
          "12589626212164087648142963156054693968143531724127210882720574876034885248674417543636718639332350307931351997411747275642172788678286702755019900752157141");
      BigInteger g = new BigInteger(
          "798714029407796779983910943217886294189424826995758502398002980609131374451706837327391684051692474365177068254749526220588451409333567287210386365320453");
      parameterSpec = new DHParameterSpec(p, g);
    } else if (algorithm.equalsIgnoreCase("RSA")) {
      ((RSAPublicKey) publicKeyTemplate).getModulusBits().setLongValue(new Long(1024));
    }

    keyPairGenerationSpec = (AlgorithmParameterSpec) new PKCS11KeyPairGenerationSpec(
        parameterSpec, publicKeyTemplate, privateKeyTemplate).setUseUserRole(true)
        .setTokenManager(tokenManager);

    keyPairGenerator.initialize(keyPairGenerationSpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    System.out.println("generated a new key pair");
    return keyPair;
  }

  public static SecretKey findCipherSecretKey(IAIKPkcs11 pkcs11Provider_, String algorithm)
      throws KeyException, GeneralSecurityException, IOException {
    return findSecretKey(pkcs11Provider_, algorithm, "cipher");
  }

  public static SecretKey findSignatureSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws KeyException, GeneralSecurityException, IOException {
    return findSecretKey(pkcs11Provider_, algorithm, "signature");
  }

  public static SecretKey findWrappingSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws KeyException, GeneralSecurityException, IOException {
    return findSecretKey(pkcs11Provider_, algorithm, "wrapping");
  }

  public static SecretKey findDerivationSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws KeyException, GeneralSecurityException, IOException {
    return findSecretKey(pkcs11Provider_, algorithm, "derivation");
  }

  private static SecretKey findSecretKey(IAIKPkcs11 pkcs11Provider_, String algorithm,
      String usage) throws KeyException, GeneralSecurityException, IOException {
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11SingleTokenKeyStore",
        pkcs11Provider_.getName());
    ByteArrayInputStream providerNameInpustStream = new ByteArrayInputStream(
        pkcs11Provider_.getName().getBytes("UTF-8"));

    // load the keystore of the PKCS#11 provider given via input stream
    tokenKeyStore.load(providerNameInpustStream, null);

    Enumeration aliases = tokenKeyStore.aliases();

    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = tokenKeyStore.getKey(keyAlias, null);
      if (key instanceof SecretKey) {
        iaik.pkcs.pkcs11.objects.SecretKey wrapperKey = (iaik.pkcs.pkcs11.objects.SecretKey) ((IAIKPKCS11SecretKey) key)
            .getKeyObject();
        boolean match = true;

        // check key attributes
        if (!wrapperKey.getKeyType().getLongValue().equals(findKeyType(algorithm))) {
          match = false;
        } else if (usage.equalsIgnoreCase("cipher")
            && (!wrapperKey.getDecrypt().getBooleanValue().booleanValue() || !wrapperKey
                .getEncrypt().getBooleanValue().booleanValue())) {
          match = false;
        } else if (usage.equalsIgnoreCase("signature")
            && (!wrapperKey.getSign().getBooleanValue().booleanValue() || !wrapperKey
                .getVerify().getBooleanValue().booleanValue())) {
          match = false;
        } else if (usage.equalsIgnoreCase("wrapping")
            && (!wrapperKey.getUnwrap().getBooleanValue().booleanValue() || !wrapperKey
                .getWrap().getBooleanValue().booleanValue())) {
          match = false;
        } else if (usage.equalsIgnoreCase("derivation")
            && !wrapperKey.getDerive().getBooleanValue().booleanValue()) {
          match = false;
        }

        if (match) {
          return (SecretKey) key;
        }

      }
    }

    // generate new key if no key was found yet
    System.out.println("No suitable secret key found");
    throw new KeyException("No suitable secret key found");
  }

  public static SecretKey generateCipherSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateSecretKey(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getCipherSecretKeyTemplate(algorithm));
  }

  public static SecretKey generateSignatureSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateSecretKey(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getSignatureSecretKeyTemplate(algorithm));
  }

  public static SecretKey generateWrappingSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateSecretKey(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getWrappingSecretKeyTemplate(algorithm));
  }

  public static SecretKey generateDerivationSecretKey(IAIKPkcs11 pkcs11Provider_,
      String algorithm) throws GeneralSecurityException {
    return generateSecretKey(pkcs11Provider_, algorithm,
        KeyTemplateDemo.getDerivationSecretKeyTemplate(algorithm));
  }

  public static SecretKey generateSecretKey(IAIKPkcs11 pkcs11Provider_, String algorithm,
      iaik.pkcs.pkcs11.objects.SecretKey secretKeyTemplate)
      throws GeneralSecurityException {
    TokenManager tokenManager = pkcs11Provider_.getTokenManager();

    KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm,
        pkcs11Provider_.getName());

    PKCS11KeyGenerationSpec keyGenerationSpec = (PKCS11KeyGenerationSpec) new PKCS11KeyGenerationSpec(
        secretKeyTemplate).setUseUserRole(false).setTokenManager(tokenManager);

    keyGenerator.init(keyGenerationSpec);

    SecretKey key = (SecretKey) keyGenerator.generateKey();
    System.out.println("generated a new secret key");
    return key;
  }

  public static Long findKeyType(String algorithm) {
    algorithm = algorithm.toLowerCase();
    if (algorithm.equals("rsa")) {
      return KeyType.RSA;
    } else if (algorithm.equals("ecdsa")) {
      return KeyType.ECDSA;
    } else if (algorithm.equals("dh")) {
      return KeyType.DH;
    } else if (algorithm.equals("dsa")) {
      return KeyType.DSA;
    } else if (algorithm.equals("aes")) {
      return KeyType.AES;
    } else if (algorithm.equals("des")) {
      return KeyType.DES;
    } else if (algorithm.equals("2des") || algorithm.equals("des2")
        || algorithm.equals("2-des") || algorithm.equals("des-2")) {
      return KeyType.DES2;
    } else if (algorithm.equals("3des") || algorithm.equals("des3")
        || algorithm.equals("3-des") || algorithm.equals("des-3")
        || algorithm.equals("tripledes") || algorithm.equals("triple-des")
        || algorithm.equals("desede")) {
      return KeyType.DES3;
    } else if (algorithm.equals("rc2")) {
      return KeyType.RC2;
    } else if (algorithm.equals("rc4")) {
      return KeyType.RC4;
    } else {
      System.out.println("algorithm not included in this demo.");
      return null;
    }
  }

}
