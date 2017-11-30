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

package demo.x509;

import iaik.pkcs.PKCS7CertList;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;

/**
 * @version File Revision <!-- $$Revision: --> 13 <!-- $ -->
 */
public class CertFactory extends java.lang.Object implements IAIKDemo {

	public void start() {

		try {
			ByteArrayOutputStream os = new ByteArrayOutputStream();

			// get the demo certificate chain
			X509Certificate[] certs = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_1024);
			// create a PKCS#7 certificate list
			PKCS7CertList pkcs7 = new PKCS7CertList();
			pkcs7.setCertificateList(certs);
			// and write it to an output stream
			pkcs7.writeTo(os);

			// get a new instance of a CertificateFactory
			CertificateFactory factory = CertificateFactory.getInstance("X.509", "IAIK");
			ByteArrayInputStream is = new ByteArrayInputStream(os.toByteArray());
			// and let it parse the input stream
			Collection c = factory.generateCertificates(is);
			Object[] certificates = c.toArray();
			System.out.println("Certificates:");
			for (int i = 0; i < certificates.length; i++) {
				System.out.println(((X509Certificate) certificates[i]).getSubjectDN());
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the CertificateFactory demo.
	 *
	 * @exception IOException if an I/O error occurs when reading required keys
	 *                        and certificates from files
	 */
	public static void main(String argv[])
	    throws IOException
	{

		Security.insertProviderAt(new IAIK(), 2);

		(new CertFactory()).start();

		System.out.println("ready...");
		System.in.read();
	}
}
