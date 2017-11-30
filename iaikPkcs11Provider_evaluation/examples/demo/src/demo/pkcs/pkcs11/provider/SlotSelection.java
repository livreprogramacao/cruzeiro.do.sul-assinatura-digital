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

import java.security.Security;
import java.util.Properties;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;

/**
 * This demo code shows how to use the getModule method of the provider class to allow slot
 * selection at runtime within the application.
 * 
 */
public class SlotSelection {

  public static void main(String[] args) throws TokenException {
    // do the selection based on the list of all slots
    selecSlot();

    // only select from those slots that contain a token
    selecToken();
  }

  /**
   * Show the slot selection with subsequent provider instantiation based on the list of all slots.
   * 
   * @throws Throwable
   *           If the demo fails.
   */
  private static void selecSlot() throws TokenException {
    Properties properties = new Properties();
    // properties.put("PKCS11_NATIVE_MODULE", "your module here.dll");
    Module module = IAIKPkcs11.getModule(properties);
    Slot[] slots = module.getSlotList(false);
    SlotInfo[] infos = new SlotInfo[slots.length];
    for (int i = 0; i < slots.length; i++) {
      infos[i] = slots[i].getSlotInfo();
    }
    printSlotInfos(infos);

    if (slots.length == 0) {
      System.err.println("No slot available!");
      return;
    }
    Slot selectedSlot = slots[0]; // select one slot

    properties.put("SLOT_ID", Long.toString(selectedSlot.getSlotID()));

    IAIKPkcs11 provider = new IAIKPkcs11(properties);
    Security.addProvider(provider);

    printListOfProviders();

    Security.removeProvider(provider.getName());
  }

  /**
   * Show the slot selection with subsequent provider instantiation based on the list of slots that
   * contain a token.
   * 
   * @throws Throwable
   *           If the demo fails.
   */
  private static void selecToken() throws TokenException {
    Properties properties = new Properties();
    // properties.put("PKCS11_NATIVE_MODULE", "your module here.dll");
    Module module = IAIKPkcs11.getModule(properties);
    Slot[] slots = module.getSlotList(true);
    TokenInfo[] infos = new TokenInfo[slots.length];
    for (int i = 0; i < slots.length; i++) {
      infos[i] = slots[i].getToken().getTokenInfo();
    }
    printTokenInfos(infos);

    if (slots.length == 0) {
      System.err.println("No token available!");
      return;
    }
    Slot selectedSlot = slots[0]; // select one slot

    properties.put("SLOT_ID", Long.toString(selectedSlot.getSlotID()));

    IAIKPkcs11 provider = new IAIKPkcs11(properties);
    Security.addProvider(provider);

    printListOfProviders();

    Security.removeProvider(provider.getName());
  }

  /**
   * Print a list of all installed providers.
   */
  private static void printListOfProviders() {
    System.out.println("----------------------------------------------------");
    java.security.Provider[] pr = java.security.Security.getProviders();
    for (int i = 0; i < pr.length; i++) {
      System.out.println("Provider #" + i + " -> " + pr[i].getInfo());
    }
    System.out.println("----------------------------------------------------");
  }

  /**
   * Print the list of slot infos.
   * 
   * @param infos
   *          The slot infos.
   */
  private static void printSlotInfos(SlotInfo[] infos) {
    System.out.println("SlotInfos");
    System.out.println("----------------------------------------------------");
    for (int i = 0; i < infos.length; i++) {
      if (i > 0) {
        System.out.println("....................................................");
      }
      System.out.println(infos[i].toString());
    }
    System.out.println("----------------------------------------------------");
  }

  /**
   * Print the list of token infos.
   * 
   * @param infos
   *          The token infos.
   */
  private static void printTokenInfos(TokenInfo[] infos) {
    System.out.println("TokenInfos");
    System.out.println("----------------------------------------------------");
    for (int i = 0; i < infos.length; i++) {
      if (i > 0) {
        System.out.println("....................................................");
      }
      System.out.println(infos[i].toString());
    }
    System.out.println("----------------------------------------------------");
  }

}
