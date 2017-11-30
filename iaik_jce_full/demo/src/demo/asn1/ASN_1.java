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

import iaik.asn1.ASN;
import iaik.asn1.ASN1;
import iaik.asn1.BIT_STRING;
import iaik.asn1.BOOLEAN;
import iaik.asn1.CON_SPEC;
import iaik.asn1.DerCoder;
import iaik.asn1.ENUMERATED;
import iaik.asn1.GeneralizedTime;
import iaik.asn1.IA5String;
import iaik.asn1.INTEGER;
import iaik.asn1.NULL;
import iaik.asn1.OCTET_STRING;
import iaik.asn1.ObjectID;
import iaik.asn1.PrintableString;
import iaik.asn1.SEQUENCE;
import iaik.asn1.SET;
import iaik.asn1.T61String;
import iaik.asn1.UTCTime;
import iaik.asn1.structures.AlgorithmID;
import iaik.utils.Util;

import java.io.IOException;

import demo.IAIKDemo;

/**
 * This class shows some demo ASN.1 applications.
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class ASN_1 implements IAIKDemo {

	/**
	 * Tests the ASN.1 implementation.
	 * <p>
	 * An ASN.1 SEQUENCE object is created composed of several different
	 * ASN.1 structures. Subsequently this ASN.1 object is printed as:
	 * <p><ul>
	 *  <li> internal Java structure
	 *  <li> DER encoded array
	 *  <li> PEM (Base64 encoded DER) encoded array
	 * </ul>
	 */
	public void start() {

		try {
			byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

			System.out.println("the following ASN.1 type (ASN1TestType) is created:\n");

			System.out.println("ASN1TestType ::= SEQUENCE {");
			System.out.println("  certificationAuthority BOOLEAN,");
			System.out.println("  serialNumber INTEGER,");
			System.out.println("  keyUsage BIT STRING,");
			System.out.println("  key OCTET STRING,");
			System.out.println("  parameter ANY,");
			System.out.println("  contextSpecific [63500] IMPLICIT Strings }");
			System.out.println();
			System.out.println("Strings ::= SEQUENCE {");
			System.out.println("  string1 PRINTABLESTRING,");
			System.out.println("  string1 T61STRING,");
			System.out.println("  string1 IA5STRING,");
			System.out.println("  time1 UTC TIME,");
			System.out.println("  time2 GENERALIZED TIME,");
			System.out.println("  testSet TestSet }");
			System.out.println();
			System.out.println("TestSet ::= SET {");
			System.out.println("  objectID OBJECT IDENTIFIER,");
			System.out.println("  type ENUMERATED,");
			System.out.println("  algorithm AlgorithmIdentifier }");
			System.out.println();
			System.out.println();

			SEQUENCE ASN1TestType = new SEQUENCE();
			ASN1TestType.addComponent(new BOOLEAN(true));
			ASN1TestType.addComponent(new INTEGER(23549));
			ASN1TestType.addComponent(new BIT_STRING(data, 2));
			ASN1TestType.addComponent(new OCTET_STRING(data));
			ASN1TestType.addComponent(new NULL());

			SET TestSet = new SET();
			TestSet.addComponent(ObjectID.pkcs7_signedData);
			TestSet.addComponent(new ENUMERATED(80000));
			TestSet.addComponent(AlgorithmID.rsa.toASN1Object());

			SEQUENCE Strings = new SEQUENCE();
			Strings.addComponent(new PrintableString("Printable String"));
			Strings.addComponent(new T61String("T61 String"));
			Strings.addComponent(new IA5String("IA5 String"));
			Strings.addComponent(new UTCTime("970625175000Z"));
			Strings.addComponent(new GeneralizedTime("19970625175000Z"));
			Strings.addComponent(TestSet);

			// tag numbers up to 2^30 are possible
			ASN1TestType.addComponent(new CON_SPEC(63500, Strings, true));

			// Now print the created ASN.1 type
			byte[] array = DerCoder.encode(ASN1TestType);

			// transmit the data ...

			ASN1 asn1 = new ASN1(array);

			System.out.println("ASN1TestType as internal Java structure:\n\n");
			System.out.println(asn1);

			System.out
			    .println("The implicitly tagged SEQUENCE (Strings) was lost during encoding.");
			System.out.println("Only the application knows the type of the lost tag.");
			System.out
			    .println("Now force the context specific ASN.1 type to be implicitly tagged...");

			CON_SPEC cs = (CON_SPEC) asn1.getComponentAt(5);
			cs.forceImplicitlyTagged(ASN.SEQUENCE);

			System.out.println("Now theASN1TestType looks like:\n");
			System.out.println(asn1);

			System.out.println("\nASN1TestType as DER encoded array (binary):\n");

			byte[] arr = asn1.toByteArray();
			int i = 0;
			while (i < arr.length) {
				System.out.println(Util.toString(arr, i, Math.min(22, arr.length - i)));
				i += 22;
			}

			System.out.println("\n\nASN1TestType as PEM encoded array (Base64 encoded DER):\n");
			System.out.println("----- BEGIN ASN1TestType -----");
			System.out.println(new String(Util.Base64Encode(arr)));
			System.out.println("----- End ASN1TestType -----");

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs a test for the ASN.1 implementation.
	 */
	public static void main(String arg[])
	    throws IOException
	{

		(new ASN_1()).start();
		System.in.read();
	}
}
