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

package demo.asn1;

import iaik.asn1.ASN1;
import iaik.asn1.CodingException;
import iaik.utils.Util;

import java.io.IOException;

/** 
 * This class tests the <b>DER</b> (<i><b>D</b>istinguished <b>E</b>ncoding <b>R</b>Rules</i>)
 * coder implementation.
 * <b>DER</b> is used for encoding certificates according to the X.509 syntax.
 * Input to the main method of this class is the name of the file containing
 * the DER encoded data.
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class DERCoder {

	/**
	 * Test the DER coder implementation.
	 *
	 * This reads a DER encoded file, decodes it, encodes it, and then compares
	 * the original DER coding to the generated DER coding.
	 *
	 * @param fileName the name of the DER encoded test file.
	 */
	public void startTest(String fileName) {

		byte[] original = null;
		byte[] encoded = null;
		int errors = 0;

		try {
			original = Util.readFile(fileName);
			ASN1 obj = new ASN1(original);

			System.out.println(obj);

			// encode!!!
			obj = new ASN1(obj.toASN1Object());
			encoded = obj.toByteArray();

		} catch (CodingException ex) {
			System.out.println("CodingException: " + ex);
			return;
		} catch (IOException ex) {
			System.out.println("Error loading file: " + ex);
			return;
		}

		System.out.println("Length original: " + original.length);
		System.out.println("Length encoded : " + encoded.length);

		for (int i = 0; i < original.length; i++)
			if (original[i] != encoded[i]) {
				errors++;
				System.out.println("Error at pos: " + i);
				for (int j = Math.max(i - 4, 0); j < i + 4; j++)
					System.out.println(j + ": " + Util.toString(original[j]) + " <> "
					    + Util.toString(encoded[j]));
				try {
					System.in.read();
				} catch (IOException ex) {
					// ignore
				}
			}

		if (errors == 0) System.out.println("No errors found.");
		else System.out.println(errors + " errors found.");
	}

	/**
	 * Performs a test for the <b>DER</b> coder implementation.
	 *
	 * @param arg the name of the file holding the DER encoded data
	 */
	public static void main(String[] arg) {

		if (arg.length == 0) {
			System.out.println("Usage: DERCoder file_to_process");
			System.exit(1);
		}

		(new DERCoder()).startTest(arg[0]);
	}
}
