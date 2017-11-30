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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Token.SessionReadWriteBehavior;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.provider.Constants;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenKeyStore;
import iaik.pkcs.pkcs11.provider.keygenerators.PKCS11KeyGenerationSpec;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.Properties;

import javax.crypto.KeyGenerator;

/**
 * This demo provides methods to change the encoding of key and certificate labels from the old
 * ASCII encoding to UTF8 encoding (which is now used per default). This is only necessary for
 * special characters. patchAllLabels changes all object labels to UTF8 without prior checks.
 * findAndPatchOldLabels verifies if the labels are already UTF8 encoded and - if not - changes
 * their encoding to UTF8.
 * 
 */
public class PatchToUTF8LabelsDemo {

  private static String testLabel1; // String: "Âèïõý"
  private static String testLabel2; // String: "äeiöüß";
  private static String testLabel3; // String: "µÚÇæ";
  private static String testLabel4 = "aNormalLabel";

  public static void main(String[] args) throws Exception {
    DemoUtils.addSoftwareProvider();

    testLabel1 = new String(Util.toByteArray("C3:82:C3:A8:C3:AF:C3:B5:C3:BD"), "UTF8"); // String:
                                                                                        // "Âèïõý"
    testLabel2 = new String(Util.toByteArray("C3:A4:65:69:C3:B6:C3:BC:C3:9F"), "UTF8"); // String:
                                                                                        // "äeiöüß";
    testLabel3 = new String(Util.toByteArray("C2:B5:C3:9A:C3:87:C3:A6"), "UTF8"); // String:
                                                                                  // "µÚÇæ";)
    PatchToUTF8LabelsDemo demo = new PatchToUTF8LabelsDemo();
    // generate old keys
    demo.generateOldKey(testLabel1);
    demo.generateOldKey(testLabel2);
    demo.generateOldKey(testLabel4);
    System.out.println("print old key labels:");
    demo.printKeyStoreEntries(false);
    // assuming all labels use old encoding -> convert all labels to utf8
    // encoding
    demo.patchAllLabels();
    System.out.println("print new utf8 encoded key labels:");
    demo.printKeyStoreEntries(true);
    demo.generateOldKey(testLabel3);
    // check if label is already utf8 encoded -> convert only not utf8 encoded
    // labels
    demo.findAndPatchOldLabels();
    System.out.println("print new utf8 encoded key labels:");
    demo.printKeyStoreEntries(true);
    demo.deleteAllDemoEntries();
  }

  private void findAndPatchOldLabels() throws Exception {

    Properties props = new Properties();
    props.put(Constants.USE_UTF8_ENCODING, "FALSE");
    IAIKPkcs11 asciiProvider = new IAIKPkcs11(props);

    System.out.println("current objects:");
    TokenKeyStore keyStore = asciiProvider.getTokenManager().getKeyStore();
    Enumeration aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = (String) aliases.nextElement();
      String utf8String = isAlreadyUtf8(alias);
      if (utf8String == null) {
        toUtf8(keyStore, alias);
        System.out.print(alias + " - will be patched");
      } else {
        System.out.print(utf8String + " - already utf8 encoded");
      }
      System.out.println();
    }
    IAIKPkcs11.discardProviderInstance(asciiProvider);

  }

  private void patchAllLabels() throws Exception {

    Properties props = new Properties();
    props.put(Constants.USE_UTF8_ENCODING, "FALSE");
    IAIKPkcs11 asciiProvider = new IAIKPkcs11(props);

    TokenKeyStore keyStore = asciiProvider.getTokenManager().getKeyStore();
    Enumeration aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = (String) aliases.nextElement();
      toUtf8(keyStore, alias);
    }
    IAIKPkcs11.discardProviderInstance(asciiProvider);

  }

  private void toUtf8(TokenKeyStore keyStore, String alias) throws Exception {
    if (keyStore.isKeyEntry(alias)) {
      IAIKPKCS11Key key = (IAIKPKCS11Key) keyStore.getKey(alias, null);
      iaik.pkcs.pkcs11.objects.Key pkcs11Key = key.getKeyObject();
      char[] label = pkcs11Key.getLabel().getCharArrayValue();
      // convert label
      if (label != null) {
        byte[] encoding = new String(label).getBytes("UTF8");
        String utf8String = new String(byteToCharArray(encoding));
        // are there other entries with this label?
        if (keyStore.containsAlias(utf8String)) {
          // can't overwrite existing entry
          IAIKPkcs11 provider = (IAIKPkcs11) keyStore.getProvider();
          Session session = provider.getTokenManager().getSession(
              SessionReadWriteBehavior.RW_SESSION);
          GenericTemplate template = new GenericTemplate();
          CharArrayAttribute labelAttr = new CharArrayAttribute(new Long(
              PKCS11Constants.CKA_LABEL));
          labelAttr.setCharArrayValue(utf8String.toCharArray());
          template.addAttribute(labelAttr);
          try {
            session.setAttributeValues(pkcs11Key, template);
          } catch (Exception e) {
            if (e.getMessage().indexOf("CKR_ATTRIBUTE_READ_ONLY") > 0) {
              // changing this label is not allowed
              // copying to new object with new label would be an option
              System.out.println("Changing label of key " + new String(label)
                  + " is not allowed.");
            } else {
              throw e;
            }
          }
        } else {
          // we can use the key store - label will be updatet bei keystore
          keyStore
              .setKeyEntry(utf8String, key, null, keyStore.getCertificateChain(alias));
          keyStore.deleteEntry(alias);
        }
      }
    } // else: certificates have no label

  }

  private String isAlreadyUtf8(String label) throws Exception {
    byte[] encoding = charToByteArray(label.toCharArray());
    String utf8String = new String(encoding, "UTF8");
    byte[] newEncoding = utf8String.getBytes("UTF8");
    if (CryptoUtils.equalsBlock(encoding, newEncoding)) {
      return utf8String;
    } else {
      return null;
    }
  }

  private void printKeyStoreEntries(boolean useUtf8) throws Exception {
    Properties props = new Properties();
    props.put(Constants.USE_UTF8_ENCODING, (useUtf8 ? "TRUE" : "FALSE"));
    IAIKPkcs11 provider = new IAIKPkcs11(props);

    TokenKeyStore keyStore = provider.getTokenManager().getKeyStore();
    Enumeration aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = (String) aliases.nextElement();
      System.out.println(alias);
    }
    IAIKPkcs11.discardProviderInstance(provider);
  }

  private void deleteAllDemoEntries() throws Exception {
    Properties props = new Properties();
    props.put(Constants.USE_UTF8_ENCODING, "TRUE");
    IAIKPkcs11 provider = new IAIKPkcs11(props);

    TokenKeyStore keyStore = provider.getTokenManager().getKeyStore();
    Enumeration aliases = keyStore.aliases();
    while (aliases.hasMoreElements()) {
      String alias = (String) aliases.nextElement();
      if (alias.startsWith(testLabel1) || alias.startsWith(testLabel2)
          || alias.startsWith(testLabel3) || alias.startsWith(testLabel4))
        keyStore.deleteEntry(alias);
    }
    IAIKPkcs11.discardProviderInstance(provider);
  }

  private byte[] charToByteArray(char[] label) {
    byte[] encoding = new byte[label.length];
    for (int i = 0; i < label.length; i++) {
      encoding[i] = (byte) (label[i] & 0xFF);
    }
    return encoding;
  }

  private char[] byteToCharArray(byte[] encoding) {
    char[] label = new char[encoding.length];
    for (int i = 0; i < encoding.length; i++) {
      label[i] = (char) (encoding[i] & 0xFF);
    }
    return label;
  }

  private void generateOldKey(String label) throws Exception {
    Properties props = new Properties();
    props.put(Constants.USE_UTF8_ENCODING, "FALSE");
    IAIKPkcs11 asciiProvider = new IAIKPkcs11(props);
    Security.addProvider(asciiProvider);
    generateKey(label, asciiProvider);
    Security.removeProvider(asciiProvider.getName());
    IAIKPkcs11.discardProviderInstance(asciiProvider);
  }

  private void generateKey(String label, IAIKPkcs11 provider) throws Exception {
    AESSecretKey template = new AESSecretKey();
    template.getLabel().setCharArrayValue(label.toCharArray());
    template.getToken().setBooleanValue(Boolean.TRUE);
    template.getValueLen().setLongValue(new Long(16));

    KeyGenerator keyGen = KeyGenerator.getInstance("AES", provider.getName());
    PKCS11KeyGenerationSpec spec = new PKCS11KeyGenerationSpec(template);
    spec.setTokenManager(provider.getTokenManager());
    keyGen.init((AlgorithmParameterSpec) spec, null);
    keyGen.generateKey();
  }

}
