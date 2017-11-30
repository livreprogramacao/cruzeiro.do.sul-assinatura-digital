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
import iaik.asn1.ASN1Object;
import iaik.asn1.CodingException;
import iaik.asn1.DerCoder;
import iaik.asn1.SEQUENCE;

import java.awt.Point;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This class shows an example of how to use private or application tags.
 * @version File Revision <!-- $$Revision: --> 12 <!-- $ -->
 */
public class PrivateASN1Type extends ASN1Object {

	private static ASN _type = new ASN(0x01, "A PRIVATE TAG", ASN.PRIVATE);

	static {
		// register this class as the implementation of the private tag 0x01
		ASN.register(_type, PrivateASN1Type.class);
	}

	// the value this ASN.1 type represents
	Point value;

	/**
	 * The default constructor.
	 */
	public PrivateASN1Type() {
		asnType = _type;
	}

	/**
	 * Create a new PrivateASN1Type form a Point.
	 *
	 * @param point a Point
	 */
	public PrivateASN1Type(Point point) {
		this();
		value = point;
	}

	/**
	 * Create a new PrivateASN1Type form the coordinates.
	 *
	 * @param x the x coordinate
	 * @param y the y coordinate
	 */
	public PrivateASN1Type(int x, int y) {
		this();
		value = new Point(x, y);
	}

	/**
	 * Sets the value of this ASN1Object. Implements the abstract class.
	 *
	 * @param object the value object the value of this ASN1Object should be set to
	 */
	public void setValue(Object object) {
		value = (Point) object;
	}

	/**
	 * Returns the value of this ASN1Object. Implements the abstract class.
	 *
	 * @return the value of this ASN1Object
	 */
	public Object getValue() {
		return value;
	}

	/**
	 * DER encodes this BOOLEAN ASN1Object and writes the result to the DerEncodeOutputStream.
	 *
	 * @param os  the output stream to which to write the data
	 */
	protected void encode(OutputStream os)
	    throws IOException
	{
		for (int i = 0; i < 4; i++) {
			// fancy encoding
			int j1 = (value.x >>> i * 8) & 0xff;
			os.write(j1);
			int j2 = (value.y >>> i * 8) & 0xff;
			os.write(j2);
		}
	}

	/**
	 * Decodes the next available data from the InputStream.
	 *
	 * @param length the length of the ASN1Object which shall be decoded
	 * @param is the input stream from which the DER encoded data is read in
	 *
	 * @exception IOException
	 *            if there is a problem with the InputStream
	 * @exception CodingException
	 *            if the bytes from <code>is</code> could not be decoded
	 */
	protected void decode(int length, InputStream is)
	    throws IOException, CodingException
	{

		if (length != 8) throw new CodingException("Wrong length: " + length);

		int x = 0;
		int y = 0;
		for (int i = 3; i >= 0; i--) {
			// fancy encoding
			x |= (is.read() << i * 8);
			y |= (is.read() << i * 8);
		}

		value = new Point(x, y);
	}

	/**
	 * Returns a string that represents the contents of this private ASN.1 object.
	 *
	 * @return the string representation
	 *
	 * @see ASN1Object#toString
	 */
	public String toString() {
		return super.toString() + "(" + value.x + ", " + value.y + ")";
	}

	public static void start() {
		try {
			// create a new sequence
			SEQUENCE seq = new SEQUENCE();
			// add our new ASN.1 type
			seq.addComponent(new PrivateASN1Type(10500, 30945));
			// another possibility
			seq.addComponent(new PrivateASN1Type(new Point(998877, 112233)));

			// DER encode the sequence
			byte[] coding = DerCoder.encode(seq);

			// and decode the sequence again
			ASN1 asn1 = new ASN1(coding);
			System.out.println(asn1);
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Test our new private ASN.1 type.
	 */
	public static void main(String[] argv)
	    throws IOException
	{
		start();
		System.out.println("private ASN.1 type o.k.!");
		System.in.read();
	}
}
