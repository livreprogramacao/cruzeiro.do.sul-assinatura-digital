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

package demo.pkcs.pkcs11.provider.wrapper;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Info;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

/**
 * This demo program lists information about a PKCS#11 module and the available slots.<br>
 * Have a look at the demo {@link GetInfo} which displays even more details.
 * <p>
 * Attention! An application which uses the PKCS#11 Provider need not ever operate on the level of
 * this sample. This small program is intended for analyzing a PKCS#11 module to give the developer
 * a hint how to configure the PKCS#11 provider.
 */
public class GetSlotList {

  static PrintWriter output_;

  static BufferedReader input_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("GetSlotList_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  public static void main(String[] args) throws IOException, TokenException {
    if ((args.length == 1) || (args.length == 2)) {
      output_
          .println("################################################################################");
      output_.println("load and initialize module: " + args[0]);
      output_.println();
      output_.flush();
      Module pkcs11Module = Module.getInstance(args[0]);

      if (args.length == 1) {
        pkcs11Module.initialize(null);
      } else {
        DefaultInitializeArgs arguments = new DefaultInitializeArgs();
        byte[] stringBytes = args[1].getBytes();
        byte[] reservedBytes = new byte[stringBytes.length + 5];
        System.arraycopy(stringBytes, 0, reservedBytes, 0, stringBytes.length);
        arguments.setReserved(reservedBytes);
        pkcs11Module.initialize(arguments);
      }

      try {
        Info info = pkcs11Module.getInfo();
        output_.println("Module information");
        output_.println("==================");
        output_.println(info);
        output_
            .println("________________________________________________________________________________");

        Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);
        output_.println("Number of available slots: " + slots.length);

        for (int i = 0; i < slots.length; i++) {
          output_
              .println("________________________________________________________________________________");
          SlotInfo slotInfo = slots[i].getSlotInfo();
          output_.print("Slot at index " + i + " has ID ");
          output_.println(slots[i].getSlotID());
          output_.println();
          output_.println("Slot information");
          output_.println("================");
          output_.println("Slot description: " + slotInfo.getSlotDescription());
          output_.println("Manufacturer: " + slotInfo.getManufacturerID());
          output_.println("Removable device: " + slotInfo.isRemovableDevice());
          output_.println("Hardware slot: " + slotInfo.isHwSlot());
          output_.println();
          if (slotInfo.isTokenPresent()) {
            output_.println("Information about token in this slot");
            output_.println("====================================");
            TokenInfo tokenInfo = slots[i].getToken().getTokenInfo();
            output_.println("Label: " + tokenInfo.getLabel());
            output_.println("Manufacturer: " + tokenInfo.getManufacturerID());
            output_.println("Model: " + tokenInfo.getModel());
            output_.println("Serial number: " + tokenInfo.getSerialNumber());
          } else {
            output_.println("There is no token in this slot.");
          }
        }
        output_
            .println("################################################################################");
      } finally {
        pkcs11Module.finalize(null);
        System.gc(); // to finalize and disconnect the pkcs11Module
      }
    } else {
      printUsage();
    }
  }

  protected static void printUsage() {
    output_.println("GetSlotList <PKCS#11 module name> [<initialization parameters>]");
    output_.println("e.g.: GetSlotList cknfast.dll");
  }

}
