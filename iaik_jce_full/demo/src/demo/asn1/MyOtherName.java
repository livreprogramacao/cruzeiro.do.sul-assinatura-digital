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
import iaik.asn1.ASN1Object;
import iaik.asn1.CON_SPEC;
import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.SEQUENCE;
import iaik.asn1.UTF8String;
import iaik.asn1.structures.OtherName;

/**
 * A simple OtherName implementation example.
 * <p>
 * This class is used by the {@link OtherNameDemo OtherNameDemo}; it 
 * implements an OtherName with type-id "1.3.6.1.4.1.2706.2.2.1.6.2"
 * where the value represents an UTF8-STRING.
 */
public class MyOtherName extends OtherName {

	/**
	 * The type id.
	 */
	public final static ObjectID TYPE_ID = new ObjectID("1.3.6.1.4.1.2706.2.2.1.6.2",
	    "MyOtherName");

	/**
	 * The OtherName value.
	 */
	private String value_;

	/**
	 * Default Constructor. Required for dynamic object creation.
	 */
	public MyOtherName() {
		// empty
	}

	/**
	 * Creates an OtherName for the given String value.
	 */
	public MyOtherName(String value) {
		if (value == null) {
			throw new IllegalArgumentException("Value must not be null!");
		}
		value_ = value;
	}

	/**
	 * Gets the type id.
	 *  
	 * @return the type id,
	 */
	public ObjectID getTypeId() {
		return TYPE_ID;
	}

	/**
	 * Gets the value of this OtherName.
	 * 
	 * @return the value as String
	 */
	public String getValue() {
		return value_;
	}

	/**
	 * Gets a String representation of this OtherName.
	 * 
	 * @return a String representation
	 */
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("\n Type-Id: " + getName());
		buf.append("\n Value: " + value_);
		return buf.toString();
	}

	/**
	 * Decodes this OtherName from its ASN.1 representation. 
	 * 
	 * @param obj the OtherName as ASN1Object
	 * 
	 * @exception CodingException if an decoding error occurs
	 */
	public void decode(ASN1Object obj)
	    throws CodingException
	{
		ObjectID typeId = (ObjectID) obj.getComponentAt(0);
		// right type-id?
		if (typeId.equals(TYPE_ID) == false) {
			throw new CodingException("Invalid OtherName type. Expected " + TYPE_ID);
		}
		// OtherName value is context specific tagged
		ASN1Object value = obj.getComponentAt(1);
		if (value.isA(ASN.CON_SPEC) == false) {
			throw new CodingException("Value component must be context-specifix tagged");
		}
		CON_SPEC conSpec = (CON_SPEC) value;
		if (conSpec.getAsnType().getTag() != 0) {
			throw new CodingException("Invalid tag of value component! Must be 0");
		}
		// CON_SPEC value is UTF8String
		value = (ASN1Object) conSpec.getValue();
		if (value.isA(ASN.UTF8String) == false) {
			throw new CodingException("Value must be UTF-8 String");
		}
		value_ = (String) value.getValue();
	}

	/**
	 * Creates an ASN.1 representation of this OtherName.
	 * 
	 * @return this OtherName as ASN1Object
	 *  
	 * @exception CodingException if an error occurs
	 */
	public ASN1Object toASN1Object()
	    throws CodingException
	{
		SEQUENCE asn1OtherName = new SEQUENCE();
		asn1OtherName.addComponent(TYPE_ID);
		asn1OtherName.addComponent(new CON_SPEC(0, new UTF8String(value_)));
		return asn1OtherName;
	}

	/**
	 * Main method.
	 * Demonstrates the usage of the {@link iaik.asn1.structures.OtherName
	 * OtherName} {@link iaik.asn1.structures.GeneralName GeneralName} type.
	 */
	public static void main(String[] args) {
		// TODO: ??
	}

}
