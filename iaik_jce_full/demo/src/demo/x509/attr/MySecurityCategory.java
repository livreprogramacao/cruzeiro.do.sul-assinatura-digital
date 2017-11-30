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

package demo.x509.attr;

import iaik.asn1.ASN;
import iaik.asn1.ASN1Object;
import iaik.asn1.CON_SPEC;
import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.PrintableString;
import iaik.x509.attr.SecurityCategory;

/**
 * A simple SecurityCategory implementation used by the
 * Clearance attribute of the {@link AttributeCertificateDemo 
 * AttributeCertificateDemo}.
 *
 * @see AttributeCertificateDemo
 * @see iaik.x509.attr.AttributeCertificate
 * @see iaik.x509.attr.SecurityCategory
 * @see iaik.x509.attr.attributes.Clearance
 */
public class MySecurityCategory extends SecurityCategory {

	/**
	 * The SecurityCategory type oid.
	 */
	public static final ObjectID type = new ObjectID("1.3.6.1.4.1.2706.2.2.1.6.1.1");

	/**
	 * This SecurityCategory has a simple String value only.
	 */
	private String s;

	/**
	 * Empty default constructor. Required for dynamic
	 * object creation only.
	 */
	public MySecurityCategory() {
	}

	/**
	 * Creates a new SecurityCategory object for the given
	 * String value.
	 * 
	 * @param s the String value
	 */
	public MySecurityCategory(String s) {
		this.s = s;
	}

	/**
	 * Gets the SecurityCategory type.
	 * 
	 * @return the type oid
	 */
	public ObjectID getType() {
		return type;
	}

	/**
	 * Decodes the SecurityCategory value from its ASN.1
	 * representation.
	 * 
	 * @param obj the ASN.1 representation of the Security
	 *            value (a PrintableString, wrapped by an
	 *            implicitly tagged CON_SPEC)
	 *            
	 * @exception CodingException if an error occurs when
	 *                            parsing the ASN.1 object           
	 */
	public void decode(ASN1Object obj)
	    throws CodingException
	{
		CON_SPEC conSpec = (CON_SPEC) obj;
		conSpec.forceImplicitlyTagged(ASN.PrintableString);
		s = (String) ((PrintableString) conSpec.getValue()).getValue();
	}

	/**
	 * Gets this SecurityCategory as ASN1Object.
	 *
	 * @return the ASN.1 representation of the Security
	 *         value (a PrintableString, wrapped by an
	 *         implicitly tagged CON_SPEC)
	 */
	public ASN1Object toASN1Object() {
		return new CON_SPEC(1, new PrintableString(s), true);
	}

	/**
	 * Gets a String representation of this SecurityCategory.
	 * 
	 * @return the String representation
	 */
	public String toString() {
		return s;
	}

}
