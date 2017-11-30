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

package demo.pkcs;

import java.io.FileInputStream;
import java.io.IOException;

import demo.util.DemoUtil;

import iaik.pkcs.PKCS7CertList;
import iaik.pkcs.PKCSException;
import iaik.x509.X509Certificate;

/**
 * This class verifies a PKCS#7 certifcate chain extractet from a
 * PKCS7CertLis t.
 * <p>
 * A PKCS7CertList represents the degenerate case of a PKCS#7 <code>
 * SignedData</code>object where there are no signers on the content.
 * PKCS7CertLists can be used for dealing with certificate chains as
 * disseminated by Netscape Navigator or Internet Explorer.
 * <p>
 * The <code>PKCS7CertList</code> is read in from a file which may have
 * been created by using the <code>writeTo</code> method of the <code>
 * iaik.pkcs.PKCS7CertList</code> class.
 * <p>
 * When starting the <code>TestPKCS7</code> test, you have to specify
 * the file name holding the <code>PKCS7CertList</code> to be parsed:
 * <p><code>TestPKCS7 &lt;file name&gt;</code><p>
 *
 * @see iaik.pkcs.PKCS7CertList
 * @version File Revision <!-- $$Revision: --> 15 <!-- $ -->
 */
public class PKCS7 {

	/**
	 * Verifies the digital signature of a certificate.
	 *
	 * @param userCert the certificate to verify
	 * @param caCert the certificate of the CA which has issued the userCert
	 *        or <code>null</code> if the userCert is a self signed certificate
	 *
	 * @return <code>true</code>, if the signature is OK, <code>false</code>
	 *         otherwise
	 */
	public static boolean verifyCertificate(X509Certificate userCert, X509Certificate caCert)
	{

		try {
			if (caCert == null) userCert.verify(); // self signed
			else userCert.verify(caCert.getPublicKey());
		} catch (Exception ex) {
			return false;
		}
		return true;
	}

	/**
	 * Verifies a chain of certificates where the user certificate is stored
	 * at index 0.
	 * The self-signed top level certificate is verified using its inherent
	 * public key. Any other certificate of the chain is verified by means
	 * of the public key derived from the issuing certificate which is located
	 * one index higher in the chain.
	 * <p>
	 * certs[0] = user certificate.
	 * certs[x] = self signed CA certificate
	 *
	 * @param certs the certificate chain to verify
	 */
	public static void verifyCertificateChain(X509Certificate[] certs) { //throws IOException {

		int anz = certs.length;

		if (!verifyCertificate(certs[anz - 1], null)) System.out
		    .println("Self signed TOPLEVEL certificate error!");
		else System.out.println("Self signed TOPLEVEL certificate OK!");

		for (int i = anz - 1; i > 0; i--)
			System.out.println(verifyCertificate(certs[i - 1], certs[i]));
	}

	/**
	 * Reads a PKCS#7 certificate chain from a file and verifies the certificates
	 * stored inside.
	 * <p>
	 * Usage:
	 * <p><code>
	 * TestPKCS7 &lt;file name&gt;
	 * </code><p>
	 *
	 * @param arg the name of the file holding the certificate chain
	 */
	public static void main(String arg[]) {

		DemoUtil.initDemos();
		if (arg.length != 1) System.out
		    .println("Usage: TestPKCS7 PKCS#7-certificate-chain-file");
		else {

			try {
				PKCS7CertList pkcs7 = new PKCS7CertList(new FileInputStream(arg[0]));
				X509Certificate[] certs = pkcs7.getCertificateList();

				verifyCertificateChain(certs);

			} catch (PKCSException ex) {
				System.out.println("PKCSException: " + ex.getMessage());
				return;
			} catch (IOException ex) {
				System.out.println("asn1parse: Error loading file: " + ex.getMessage());
				return;
			}
		}
	}
}
