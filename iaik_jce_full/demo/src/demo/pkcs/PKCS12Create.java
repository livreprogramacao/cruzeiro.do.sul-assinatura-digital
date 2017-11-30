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

import iaik.asn1.ObjectID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.KeyBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * @version File Revision <!-- $$Revision: --> 23 <!-- $ -->
 */
public class PKCS12Create implements IAIKDemo {

	public void start() {
		start(null);
	}

	public void start(String fileName) {

		try {

			// get the certificate chain
			X509Certificate[] certs = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_1024);
			// get the private key
			PrivateKey privateKey = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_1024);

			System.out.println("creating PKCS#12 object...");
			// we set the commonName as friendlyName attribute
			Name subject = (Name) certs[0].getSubjectDN();
			String friendlyName = subject.getRDN(ObjectID.commonName);
			// since SubjectKeyIdentifier is included use it as keyId
			byte[] keyId = ((SubjectKeyIdentifier) certs[0]
			    .getExtension(SubjectKeyIdentifier.oid)).get();
			KeyBag keyBag = new KeyBag(privateKey, friendlyName, keyId);

			CertificateBag[] certBags = new CertificateBag[certs.length];
			certBags[0] = new CertificateBag(certs[1]);
			Name caSubject = (Name) certs[1].getSubjectDN();
			certBags[0].setFriendlyName(caSubject.getRDN(ObjectID.commonName));
			// this certificate corresponds to the private key; I think :-)
			certBags[1] = new CertificateBag(certs[0]);
			certBags[1].setFriendlyName(friendlyName);
			certBags[1].setLocalKeyID(keyId);

			char[] password = "test".toCharArray();
			PKCS12 test_write = new PKCS12(keyBag, certBags, false);
			test_write.encrypt(password);
			OutputStream os;
			if (fileName == null) {
				os = new ByteArrayOutputStream();
			} else {
				os = new FileOutputStream(fileName);
			}
			test_write.writeTo(os);
			os.close();

			// now parse the PKCS#12 object
			System.out.println("Parsing PKCS#12 object...");
			PKCS12 pkcs12 = null;
			InputStream is = null;
			if (fileName == null) {
				is = new ByteArrayInputStream(((ByteArrayOutputStream) os).toByteArray());
				pkcs12 = new PKCS12(is);
			} else {
				is = new FileInputStream(fileName);
				pkcs12 = new PKCS12(is);
			}
			System.out.println("Verifying MAC...");
			// verify the MAC
			if (!pkcs12.verify(password)) {
				throw new PKCSException("Verification error!");
			}
			// dercrypt the PKCS#12 object
			System.out.println("Decrypting PKCS#12 object...");
			pkcs12.decrypt(password);
			// get the private key
			KeyBag kB = pkcs12.getKeyBag();
			PrivateKey pk = kB.getPrivateKey();
			System.out.println("Key is " + pk.getAlgorithm() + ", " + Util.getKeyLength(pk)
			    + " bits");
			// get the certificates
			CertificateBag[] certBag = pkcs12.getCertificateBags();
			java.security.cert.Certificate[] certChain = CertificateBag
			    .getCertificates(certBag);
			// convert to IAIK certs      
			X509Certificate[] certArray = Util.convertCertificateChain(certChain);
			// we may want to have the end user cert at index 0
			X509Certificate[] tmpCertArray = Util.arrangeCertificateChain(certArray, false);
			if (tmpCertArray == null) {
				System.out.println("Cert chain broken or certs do not belond to same chain");
			} else {
				certArray = tmpCertArray;
			}
			System.out.println("Certs included belong to: ");
			int chainLen = certArray.length;
			for (int i = 0; i < chainLen; i++) {
				System.out.println("Subject [" + i + "]: " + certArray[i].getSubjectDN());
				System.out.println("Issuer  [" + i + "]: " + certArray[i].getIssuerDN());
			}

			// or we may search the cert belonging to the private key based on the localkeyID attribute
			X509Certificate endUserCert = null;
			byte[] localKeyID = kB.getLocalKeyID();
			if (localKeyID != null) {
				// check the cert bags for same locale key id
				for (int i = 0; i < certBag.length; i++) {
					byte[] certID = certBag[i].getLocalKeyID();
					if ((certID != null) && (CryptoUtils.equalsBlock(certID, localKeyID))) {
						endUserCert = certBag[i].getCertificate();
						break;
					}
				}
			}
			if (endUserCert != null) {
				System.out.println("End User Cert:");
				System.out.println(endUserCert.toString(true));
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Creates a PKCS#12 file from a self-created certificate and key pair.
	 *
	 * @exception IOException
	 *            if an I/O error occurs when reading required keys
	 *            and certificates from files
	 */
	public static void main(String[] argv)
	    throws IOException
	{

		DemoUtil.initDemos();
		PKCS12Create p12 = new PKCS12Create();
		if (argv.length != 0) p12.start(argv[0]);
		else p12.start(null);

		System.out.println("No errors...");
		System.in.read();
	}
}
