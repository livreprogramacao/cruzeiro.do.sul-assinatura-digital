// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2013 Stiftung Secure Information and
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

package demo.util;

import iaik.security.provider.IAIK;

import java.io.IOException;
import java.security.Security;

/**
 * Some basic utility methods.
 */
public class DemoUtil {

	/** Debug flag for all demos */
	public final static boolean DEMO_DEBUG = true;

	private final static String[] GREETING = {
	    "*                                                                            *",
	    "*             Welcome to the IAIK-JCE Demo Programs                          *",
	    "*                                                                            *",
	    "* These simple programs show how to use the IAIK-JCE library. Please see     *",
	    "* the documentation and the demo source code for more information.           *",
	    "*                                                                            *",
	    "*                                                                            *",
	    "* NOTE that some of the demos require certificates to work, they are taken   *",
	    "* from a keystore file (jce.keystore) located in your current working        *",
	    "* directory. If yet not exist, the keystore can be generated by calling      *",
	    "* demo.keystore.SetupKeyStore.                                               *",
	    "*                                                                            *",
	    "", };

	private static boolean initialized = false;

	private DemoUtil() {
		// empty
	}

	/** 
	 * Perform some initial setup to allow the demos to work.
	 */
	public synchronized static void initDemos() {
		initDemos(null);
	}

	/** 
	 * Perform some initial setup to allow the demos to work.
	 * 
	 * @param arg "1" for installing IAIK provider by calling <code>Security.insertProviderAt(new IAIK(), 1);</code>
	 *            "2" for installing IAIK provider by calling <code>Security.insertProviderAt(new IAIK(), 2);</code>
	 *            in any other case the IAIK provider is installed by calling <code>IAIK.addAsProvider(true)</code>
	 */
	public synchronized static void initDemos(String arg) {
		if (initialized) {
			return;
		}
		initialized = true;
		for (int i = 0; i < GREETING.length; i++) {
			System.out.println(GREETING[i]);
		}
		addIaikProvider(arg);
	}

	/**
	 * Adds the IAIK provider.
	 * 
	 * @param arg "1" for installing IAIK provider by calling <code>Security.insertProviderAt(new IAIK(), 1);</code>
	 *            "2" for installing IAIK provider by calling <code>Security.insertProviderAt(new IAIK(), 2);</code>
	 *            in any other case the IAIK provider is installed by calling <code>IAIK.addAsProvider(true)</code>  
	 */
	public static void addIaikProvider(String arg) {
		if (arg != null) {
			if (arg.equals("1")) {
				IAIK.addAsProvider(true);
			} else if (arg.equals("2")) {
				Security.insertProviderAt(new IAIK(), 2);
			} else {
				IAIK.addAsProvider(true);
			}
		} else {
			IAIK.addAsProvider(true);
		}

	}

	/**
	 * Wait for the user to press the return key on System.in.
	 */
	public static void waitKey() {
		try {
			System.out.println("Hit the <RETURN> key.");
			do {
				System.in.read();
			} while (System.in.available() > 0);
		} catch (IOException e) {
			// ignore
		}
	}

}
