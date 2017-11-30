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

package demo.x509.qualified;

import iaik.asn1.ASN1Object;
import iaik.asn1.ObjectID;
import iaik.asn1.PrintableString;
import iaik.x509.extensions.qualified.structures.QCStatementInfo;

/**
 * Implements a private QCStatement.
 * <p>
 * This class demonstrates how private QCStatements may be implemented by extending
 * the {@link iaik.x509.extensions.qualified.structures.QCStatementInfo QCStatementInfo}
 * class. For using this private statement it has to be {@link 
 * iaik.x509.extensions.qualified.structures.QCStatement#register(ObjectID, Class)
 * registered} within the QCStatement framework:
 * <pre>
 * QCStatement.register(MyPrivateQCStatement.statementID, MyPrivateQCStatement.class);
 * </pre>
 * See the {@link demo.x509.qualified.QualifiedCert QualifiedCert} demo on
 * how to use.
 * <p>
 * The ASN.1 structure of the statement info belonging to this private QCStatement
 * is rather simple and only consists of a PrintableString holding a statement 
 * message:
 * <pre>
 * statementMessage ::= PrintableString
 * </pre>
 * @version File Revision <!-- $$Revision: --> 8 <!-- $ -->
 */
public class MyPrivateQCStatement extends QCStatementInfo {

	/**
	 * The statement id for this private QC statement.
	 */
	public static final ObjectID statementID = new ObjectID("1.3.6.1.4.1.2706.2.2.1.4",
	    "MyPrivateQCStatement");

	String myPrivateStatement;

	/**
	 * Default constructor.
	 */
	public MyPrivateQCStatement() {
	}

	/**
	 * Creates a private QC statement for the given statement string.
	 *
	 * @param statement the statement message
	 */
	public MyPrivateQCStatement(String statement) {
		myPrivateStatement = statement;
	}

	/**
	 * Returns the statement ID.
	 *
	 * @return the statement id
	 */
	public ObjectID getStatementID() {
		return statementID;
	}

	/**
	 * Gets the statement message.
	 * 
	 * @return the statement message
	 */
	public String getStatement() {
		return myPrivateStatement;
	}

	/**
	 * Decodes the statement info.
	 *
	 * @param obj the statement info as ASN1Object
	 */
	public void decode(ASN1Object obj) {
		myPrivateStatement = (String) obj.getValue();
	}

	/**
	 * Returns an ASN.1 representation of this statement info.
	 *
	 * @return this statement info as ASN1Object
	 */
	public ASN1Object toASN1Object() {
		return new PrintableString(myPrivateStatement);
	}

	/**
	 * Returns a string representation of the statement info
	 *
	 * @return a string representation of the statement info
	 */
	public String toString() {
		return myPrivateStatement + "\n";
	}

}
