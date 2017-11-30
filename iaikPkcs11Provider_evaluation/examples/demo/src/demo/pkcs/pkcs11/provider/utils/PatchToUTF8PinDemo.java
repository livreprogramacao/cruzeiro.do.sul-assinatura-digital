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
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.provider.Constants;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.TokenManager;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Properties;

/**
 * This demo provides a method to change the encoding of the current PIN from ASCII to UTF8 (which
 * is now used per default). At first the demo logs in with the given PIN while UTF8 encoding is
 * disabled and changes the PIN to a dummy PIN (without special characters). Afterwards, UTF8
 * encoding is enabled again to change the dummy PIN to the given pin using UTF8 encoding.
 * 
 */

public class PatchToUTF8PinDemo {

  private static BufferedReader reader_;
  private static PrintWriter output_;

  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      printUsage();
      throw new IOException("missing arguments");
    }
    reader_ = new BufferedReader(new InputStreamReader(System.in));
    PatchToUTF8PinDemo demo = new PatchToUTF8PinDemo();
    String pinString = null;
    boolean userType = Session.UserType.USER;
    if (args[0].equalsIgnoreCase("USER")) {
      userType = Session.UserType.USER;
    } else if (args[0].equalsIgnoreCase("SO")) {
      userType = Session.UserType.SO;
    } else {
      printUsage();
      throw new IOException("unknown user type");
    }
    if (args.length > 1)
      pinString = args[1];
    demo.patchPin(userType, pinString);
  }

  private void patchPin(boolean isUserType, String pinArg) throws Exception {
    // get ascii provider for old pin
    IAIKPkcs11 asciiProvider = getProvider(false);
    TokenManager tokenManager = asciiProvider.getTokenManager();
    Session session = tokenManager.getSession(Token.SessionReadWriteBehavior.RW_SESSION);

    String userTypeName = (isUserType == Session.UserType.USER) ? "user"
        : "security officer";
    System.out.print("Enter current " + userTypeName + " PIN: ");
    System.out.flush();
    String pinString;
    if (pinArg != null) {
      pinString = pinArg;
      System.out.println(pinString);
    } else {
      pinString = reader_.readLine();
    }
    char[] pin = pinString.toCharArray();
    tokenManager.login(session, !isUserType, pin);

    // convert pin to utf8 encoding
    byte[] encoding = pinString.getBytes("UTF8");
    String utf8String = new String(byteToCharArray(encoding));
    if (isUserType) {
      tokenManager.setUserPIN(session, pin, utf8String.toCharArray());
    } else {
      session.setPIN(pin, utf8String.toCharArray());
    }
    session.closeSession();

    // test login with utf8 encoding
    IAIKPkcs11.discardProviderInstance(asciiProvider);
    IAIKPkcs11 utf8Provider = getProvider(true);
    tokenManager = utf8Provider.getTokenManager();
    tokenManager.login(!isUserType, pin);
    IAIKPkcs11.discardProviderInstance(utf8Provider);

  }

  private IAIKPkcs11 getProvider(boolean useUtf8Encoding) {
    Properties props = new Properties();
    props.put(Constants.USE_UTF8_ENCODING, (useUtf8Encoding ? "TRUE" : "FALSE"));
    return new IAIKPkcs11(props);
  }

  private char[] byteToCharArray(byte[] encoding) {
    char[] label = new char[encoding.length];
    for (int i = 0; i < encoding.length; i++) {
      label[i] = (char) (encoding[i] & 0xFF);
    }
    return label;
  }

  public static void printUsage() {
    output_.println("Usage: PatchToUTF8PinDemo User/SO [<Pin>]");
    output_.println(" e.g.: PatchToUTF8PinDemo User passwörd");
  }

}
