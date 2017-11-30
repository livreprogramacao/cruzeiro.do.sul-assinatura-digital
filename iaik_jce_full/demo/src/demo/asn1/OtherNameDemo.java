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

import java.io.IOException;

import demo.IAIKDemo;

import iaik.asn1.ASN1Object;
import iaik.asn1.DerCoder;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.OtherName;

/**
 * Demonstrates the usage of the {@link iaik.asn1.structures.OtherName
 * OtherName} {@link iaik.asn1.structures.GeneralName GeneralName} type.
 * 
 * @see iaik.asn1.structures.GeneralName
 * @see iaik.asn1.structures.OtherName
 */
public class OtherNameDemo implements IAIKDemo {

	/**
	 * Default constructor.
	 */
	public OtherNameDemo() {
		// empty
	}

	/**
	 * Starts the demo.
	 */
	public void start() {

		try {
			// register specific OtherName implementation
			OtherName.register(MyOtherName.TYPE_ID, MyOtherName.class);

			// the GeneralName of type OtherName
			MyOtherName myOtherName = new MyOtherName("This is an other name!");
			GeneralName generalName = new GeneralName(GeneralName.otherName, myOtherName);

			// encode
			byte[] encodedGeneralName = DerCoder.encode(generalName.toASN1Object());
			// decode
			ASN1Object asn1GeneralName = DerCoder.decode(encodedGeneralName);
			generalName = new GeneralName(asn1GeneralName);

			// GeneralName of type OtherName?
			if (generalName.getType() == GeneralName.otherName) {
				// get the inherent name
				Object name = generalName.getName();
				if (name instanceof OtherName) {
					OtherName otherName = (OtherName) name;
					// check OtherName type (only required if you have more OtherNames registered)
					if (otherName.getTypeId().equals(MyOtherName.TYPE_ID)) {
						myOtherName = (MyOtherName) otherName;
						String value = myOtherName.getValue();
						System.out.println(value);
					}
				} else {
					// no OtherName for the specific type-id is registered
				}
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Main Method.
	 */
	public static void main(String[] argv)
	    throws IOException
	{
		(new OtherNameDemo()).start();
		System.in.read();
	}
}
