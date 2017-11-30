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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import iaik.apps.util.passphrase.PassphrasePrompt;
import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Info;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.SlotInfo;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.X509AttributeCertificate;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.provider.DefaultLoginManager;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * This demo program lists information about a PKCS#11 module, the available slots, the available
 * tokens and the objects on them. It takes the name of the module and prompts the user PIN. If the
 * user PIN is not available, the program will list only public objects but no private objects; i.e.
 * as defined in PKCS#11 for public read-only sessions. <br>
 * Attention! An application which uses the PKCS#11 Provider need not ever operate on the level of
 * this sample. This small program is intended for analyzing a PKCS#11 module to give the developer
 * a hint how to configure the PKCS#11 provider.
 */
public class GetInfo {

  static PrintWriter output_;

  static BufferedReader input_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("GetInfo_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  public static void main(String[] args) throws TokenException, IOException {
    if ((args.length == 1) || (args.length == 2) || (args.length == 3)) {
      output_
          .println("################################################################################");
      output_.println("load and initialize module: " + args[0]);
      output_.flush();
      Module pkcs11Module = Module.getInstance(args[0]);

      if (args.length < 3) {
        pkcs11Module.initialize(null);
      } else {
        DefaultInitializeArgs arguments = new DefaultInitializeArgs();
        byte[] stringBytes = args[2].getBytes();
        byte[] reservedBytes = new byte[stringBytes.length + 5];
        System.arraycopy(stringBytes, 0, reservedBytes, 0, stringBytes.length);
        arguments.setReserved(reservedBytes);
        pkcs11Module.initialize(arguments);
      }

      try {
        Info info = pkcs11Module.getInfo();
        output_.println(info);
        output_
            .println("################################################################################");

        output_
            .println("################################################################################");
        output_.println("getting list of all slots");
        Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.ALL_SLOTS);

        for (int i = 0; i < slots.length; i++) {
          output_
              .println("________________________________________________________________________________");
          SlotInfo slotInfo = slots[i].getSlotInfo();
          output_.print("Slot with ID: ");
          output_.println(slots[i].getSlotID());
          output_
              .println("--------------------------------------------------------------------------------");
          output_.println(slotInfo);
          output_
              .println("________________________________________________________________________________");
        }
        output_
            .println("################################################################################");

        output_
            .println("################################################################################");
        output_.println("getting list of all tokens");
        Slot[] slotsWithToken = pkcs11Module
            .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
        Token[] tokens = new Token[slotsWithToken.length];

        for (int i = 0; i < slotsWithToken.length; i++) {
          output_
              .println("________________________________________________________________________________");
          tokens[i] = slotsWithToken[i].getToken();
          TokenInfo tokenInfo = tokens[i].getTokenInfo();
          output_.print("Token in slot with ID: ");
          output_.println(tokens[i].getSlot().getSlotID());
          output_
              .println("--------------------------------------------------------------------------------");
          output_.println(tokenInfo);

          output_.println("supported Mechanisms:");
          Mechanism[] supportedMechanisms = tokens[i].getMechanismList();
          for (int j = 0; j < supportedMechanisms.length; j++) {
            output_
                .println("--------------------------------------------------------------------------------");
            output_.println("Mechanism Name: " + supportedMechanisms[j].getName());
            MechanismInfo mechanismInfo = tokens[i]
                .getMechanismInfo(supportedMechanisms[j]);
            output_.println(mechanismInfo);
            output_
                .println("--------------------------------------------------------------------------------");
          }
          output_
              .println("________________________________________________________________________________");
        }
        output_
            .println("################################################################################");

        output_
            .println("################################################################################");
        output_.println("listing objects on tokens");

        for (int i = 0; i < tokens.length; i++) {
          output_
              .println("________________________________________________________________________________");
          output_.println("listing objects for token: ");
          TokenInfo tokenInfo = tokens[i].getTokenInfo();
          output_.println(tokenInfo);
          Session session = tokens[i].openSession(Token.SessionType.SERIAL_SESSION,
              Token.SessionReadWriteBehavior.RO_SESSION, null, null);

          try {
            if (tokenInfo.isLoginRequired()) {
              if (tokenInfo.isProtectedAuthenticationPath()) {
                session.login(Session.UserType.USER, null); // the token prompts the PIN by other
                                                            // means; e.g. PIN-pad
              } else {
                char[] pin;
                if (args.length >= 2)
                  pin = args[1].toCharArray();
                else {
                  DefaultLoginManager loginManager = new DefaultLoginManager();
                  PassphrasePrompt pinPrompt = loginManager.getPassphrasePrompt();
                  pinPrompt.setCancelAllowed(true);
                  pinPrompt
                      .setMessage("Enter user-PIN or close dialog to list just public objects: ");
                  pinPrompt.setProtectedResourceInfo(tokenInfo.getLabel());
                  pin = pinPrompt.promptPassphrase();
                }
                output_.println();
                output_.print("listing all" + ((pin != null) ? "" : " public")
                    + " objects on token");
                output_.println();
                if (pin != null) {
                  // login user
                  session.login(Session.UserType.USER, pin);
                }
              }
            }
            SessionInfo sessionInfo = session.getSessionInfo();
            output_.println(" using session:");
            output_.println(sessionInfo);

            session.findObjectsInit(null);
            Object[] objects = session.findObjects(1);

            CertificateFactory x509CertificateFactory = null;
            while (objects.length > 0) {
              Object object = objects[0];
              output_
                  .println("--------------------------------------------------------------------------------");
              output_.println("Object with handle: " + objects[0].getObjectHandle());
              output_.println(object);
              if (object instanceof X509PublicKeyCertificate) {
                try {
                  byte[] encodedCertificate = ((X509PublicKeyCertificate) object)
                      .getValue().getByteArrayValue();
                  if (x509CertificateFactory == null) {
                    x509CertificateFactory = CertificateFactory.getInstance("X.509");
                  }
                  Certificate certificate = x509CertificateFactory
                      .generateCertificate(new ByteArrayInputStream(encodedCertificate));
                  output_
                      .println("................................................................................");
                  output_.println("The decoded X509PublicKeyCertificate is:");
                  output_.println(certificate.toString());
                  output_
                      .println("................................................................................");
                } catch (Exception ex) {
                  output_
                      .println("Could not decode this X509PublicKeyCertificate. Exception is: "
                          + ex.toString());
                }
              } else if (object instanceof X509AttributeCertificate) {
                try {
                  byte[] encodedCertificate = ((X509AttributeCertificate) object)
                      .getValue().getByteArrayValue();
                  if (x509CertificateFactory == null) {
                    x509CertificateFactory = CertificateFactory.getInstance("X.509");
                  }
                  Certificate certificate = x509CertificateFactory
                      .generateCertificate(new ByteArrayInputStream(encodedCertificate));
                  output_
                      .println("................................................................................");
                  output_.println("The decoded X509AttributeCertificate is:");
                  output_.println(certificate.toString());
                  output_
                      .println("................................................................................");
                } catch (Exception ex) {
                  output_
                      .println("Could not decode this X509AttributeCertificate. Exception is: "
                          + ex.toString());
                }
              }
              // test the (deep) cloning feature
              // Object clonedObject = (Object) object.clone();
              output_
                  .println("--------------------------------------------------------------------------------");
              objects = session.findObjects(1);
            }
            session.findObjectsFinal();
          } finally {
            session.closeSession();
          }
          output_
              .println("________________________________________________________________________________");
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
    output_.println("GetInfo <PKCS#11 module name> [pin] [<initialization parameters>]");
    output_.println("e.g.: GetInfo pk2priv.dll");
  }

}
