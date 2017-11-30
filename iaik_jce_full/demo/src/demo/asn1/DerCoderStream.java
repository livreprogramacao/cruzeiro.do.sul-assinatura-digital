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
import iaik.asn1.CON_SPEC;
import iaik.asn1.DerCoder;
import iaik.asn1.OCTET_STRING;
import iaik.asn1.SEQUENCE;
import iaik.utils.Util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import demo.IAIKDemo;

/**
 * This class demonstrates the encoding and decoding of ANS.1 to and from
 * streams.
 * @version File Revision <!-- $$Revision: --> 14 <!-- $ -->
 */
public class DerCoderStream implements IAIKDemo {

	public void start() {
		try {
			byte[] data = { 1, 2, 3, 4, 5 };
			// the output stream where the data will be written to
			ByteArrayOutputStream os = new ByteArrayOutputStream();

			SEQUENCE seq = new SEQUENCE(true);
			OCTET_STRING ocstr = new OCTET_STRING(new ByteArrayInputStream(data), 2);
			CON_SPEC cs = new CON_SPEC(0, ocstr, true);
			seq.addComponent(cs);
			DerCoder.encodeTo(seq, os);
			byte[] b = os.toByteArray();
			System.out.println(Util.toString(b));
			System.out.println(new ASN1(b));

			os.reset();
			seq = new SEQUENCE(true);
			seq.addComponent(new OCTET_STRING(new ByteArrayInputStream(data), 2));
			DerCoder.encodeTo(seq, os);
			System.out.println(Util.toString(os.toByteArray()));

			os.reset();
			// create a new sequence with indefinite length encoding
			seq = new SEQUENCE(true);
			// create an OCTET_STRING with block length 2 from an InputStream
			ocstr = new OCTET_STRING();
			//enforce indefinite length encoding
			ocstr.setIndefiniteLength(true);
			OCTET_STRING firstComp = new OCTET_STRING(new ByteArrayInputStream(data), 2);
			firstComp.setIndefiniteLength(true);
			OCTET_STRING secondComp = new OCTET_STRING(new byte[] { 65, 66, 67, 68, 13, 10, 13,
			    10 });
			ocstr.addComponent(firstComp);
			// add this data at pos 0 (before the data of the input stream is added
			ocstr.addComponent(secondComp, 0);

			// add the octet string to the sequencd
			seq.addComponent(ocstr);
			// DER encode the sequence and write the data to the os
			seq.setIndefiniteLength(true);
			DerCoder.encodeTo(seq, os);
			System.out.println();
			System.out.println(Util.toString(os.toByteArray()));

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	public static void main(String[] argv)
	    throws IOException
	{
		(new DerCoderStream()).start();
		System.in.read();
	}
}
