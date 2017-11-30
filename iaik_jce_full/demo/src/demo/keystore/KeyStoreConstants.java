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

package demo.keystore;

/**
 * @version File Revision <!-- $$Revision: --> 11 <!-- $ -->
 */
public interface KeyStoreConstants {
	public final static String CA_RSAPSS = "CA.RSAPSS";
	public final static String CA_RSA = "CA.RSA";
	public final static String CA_DSA = "CA.DSA";
	public final static String AC_ISSUER = "AC.ISSUER"; // attribute certificate issuer
	public final static String RSA_512 = "RSA.512";
	public final static String RSA_1024 = "RSA.1024";
	public final static String RSA_2048 = "RSA.2048";
	public final static String RSAPSS_1024 = "RSAPSS.1024";
	public final static String RSAOAEP_1024 = "RSAOAEP.1024";
	public final static String DSA_512 = "DSA.512";
	public final static String DSA_1024 = "DSA.1024";
	public final static String DSA_2048 = "DSA.2048";
	public final static String DH_512 = "DH.512";
	public final static String DH_1024 = "DH.1024";
	public final static String DH_2048 = "DH.2048";
	public final static String KS_FILENAME = "jce.keystore";
	final static char[] KS_PASSWORD = "topSecret".toCharArray();
}
