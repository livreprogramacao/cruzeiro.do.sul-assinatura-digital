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

import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenManager;
import iaik.pkcs.pkcs11.provider.keypairgenerators.PKCS11KeyPairGenerationSpec;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11PrivateKey;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509Certificate;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;

import demo.pkcs.pkcs11.provider.SelfSignedCertificate;

public class Util {

  public static KeyAndCertificate getSignatureKeyAndCert(IAIKPkcs11 pkcs11Provider,
      boolean crlSigning) throws GeneralSecurityException, IOException,
      RFC2253NameParserException {

    KeyStore tokenKeyStore = pkcs11Provider.getTokenManager().getKeyStore();
    PrivateKey signatureKey = null;
    X509Certificate signerCertificate = null;

    // we simply take the first keystore, if there are serveral
    Enumeration aliases = tokenKeyStore.aliases();

    // and we take the first signature (private) key for simplicity
    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      Key key = tokenKeyStore.getKey(keyAlias, null);
      if (key instanceof java.security.interfaces.RSAPrivateKey) {
        Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
        if (certificateChain != null && certificateChain.length > 0) {
          X509Certificate certificate = (X509Certificate) certificateChain[0];
          boolean[] keyUsage = certificate.getKeyUsage();
          if ((keyUsage == null) || (!crlSigning && (keyUsage[0] || keyUsage[1]))
              || (crlSigning && keyUsage[6])) { // check for digital signature or non-repudiation or
                                                // crl if set, but also accept if none set
            iaik.pkcs.pkcs11.objects.PrivateKey pkcs11PrivateKeyObject = (iaik.pkcs.pkcs11.objects.PrivateKey) ((IAIKPKCS11PrivateKey) key)
                .getKeyObject();
            if (pkcs11PrivateKeyObject.getSign().getBooleanValue().booleanValue()) {
              signatureKey = (PrivateKey) key;
              signerCertificate = certificate;
              break;
            }
          }
        }
      }
    }

    if (signatureKey == null) {
      System.out.println("Found no signature key. Generating a new one.");

      RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
      privateKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // temporary session key
      privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE); // only accessible after log-in
      privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE); // key should not leave the
                                                                       // token
      privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

      RSAPublicKey publicKeyTemplate = new RSAPublicKey();
      byte[] publicExponentBytes = { 0x01, 0x00, 0x01 };
      publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
      publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
      publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE); // temporary session key
      publicKeyTemplate.getModulusBits().setLongValue(new Long(1024));

      TokenManager tokenManager = pkcs11Provider.getTokenManager();
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
          pkcs11Provider.getName());

      AlgorithmParameterSpec keyPairGenerationSpec = (AlgorithmParameterSpec) new PKCS11KeyPairGenerationSpec(
          publicKeyTemplate, privateKeyTemplate).setUseUserRole(true).setTokenManager(
          tokenManager);

      keyPairGenerator.initialize(keyPairGenerationSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      signatureKey = keyPair.getPrivate();

      SelfSignedCertificate certCreatorHelper = new SelfSignedCertificate(
          "CN=Max Mustermann,OU=company,C=AT", null, "maxmustermann");
      certCreatorHelper.setKeyPair(keyPair);
      signerCertificate = certCreatorHelper.createCertificate();
    }

    return new KeyAndCertificate(signatureKey,
        new X509Certificate[] { signerCertificate });
  }

}
