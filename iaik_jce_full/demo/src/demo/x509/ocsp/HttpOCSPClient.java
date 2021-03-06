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

package demo.x509.ocsp;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs12.CertificateBag;
import iaik.pkcs.pkcs12.KeyBag;
import iaik.pkcs.pkcs12.PKCS12;
import iaik.security.provider.IAIK;
import iaik.utils.ASN1InputStream;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.ocsp.OCSPException;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.UnknownResponseException;
import iaik.x509.ocsp.net.HttpOCSPRequest;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Collection;

/**
 * A simple OCSP client.
 * <p>
 * This client is part of the IAIK OCSP client - server demo. This class does
 * exactly the same as demo class {@link demo.x509.ocsp.OCSPClient OCSPClient}
 * but uses class {@link iaik.x509.ocsp.net.HttpOCSPRequest HttpOCSPRequest} for
 * connecting to the server.
 * <p>
 * The keys and certificates required for this demo are obtained from the
 * IAIK-JCE demo keystore "jce.keystore" which may be generated by running the
 * {@link demo.keystore.SetupKeyStore SetupKeyStore} program. <br>
 * This class extends the {@link demo.x509.ocsp.OCSP OCSP} class for using its
 * request creation/response parsing methods.
 * <p>
 * If you want to connect to another OCSP server than the IAIK OCSP demo
 * {@link demo.x509.ocsp.OCSPServer server} (listening on localhost, port 9999)
 * you may specify the URL of the server and the target cert chain to be asked
 * for revocation status when starting the client:
 * 
 * <pre>
 * java  HttpOCSPClient &lt;responderUrl&gt; &lt;targetCertsFile&gt;
 * </pre>
 * 
 * The certs given in the target cert file may be in X.509 or PKCS#7 format and
 * shall contain the target cert at index 0. Alternatively you may specify
 * target cert and target issuer cert in separate files:
 * 
 * <pre>
 * java  HttpOCSPClient &lt;responderUrl&gt; &lt;targetCertFile&gt; &lt;targetIssuerCertFile&gt;
 * </pre>
 * <p>
 * If you want to send a signed request, you additionally may specify the
 * PKCS#12 from where to read certs and key for signing the request:
 * 
 * <pre>
 * java  HttpOCSPClient &lt;responderUrl&gt; &lt;targetCertsFile&gt; [&lt;pkcs12File&gt; &lt;password&gt;]]
 * </pre>
 * 
 * or (when using separate files for target cert and target issuer cert):
 * 
 * <pre>
 * java  HttpOCSPClient &lt;responderUrl&gt; &lt;targetCertFile&gt; &lt;targetIssuerCertFile&gt; [&lt;pkcs12File&gt; &lt;password&gt;]]
 * </pre>
 * 
 * @see demo.x509.ocsp.OCSPServer
 * @see demo.x509.ocsp.OCSPServerThread
 * @see demo.x509.ocsp.OCSP
 * @version File Revision <!-- $$Revision: --> 28 <!-- $ -->
 */
public class HttpOCSPClient extends OCSP {

	// the url of the OCSP responder to connect to
	String responderUrl;

	/**
	 * Default constructor. Reads required keys and certificates from the demo
	 * keystore.
	 * 
	 * @exception IOException
	 *              if an error occurs when loading the keystore
	 */
	public HttpOCSPClient()
	    throws IOException
	{
		super();
		responderUrl = "http://localhost:9999";
	}

	/**
	 * Starts the OCSP client. If responder URL and target cert file have not been
	 * supplied via command line, a request is created for the target certs, read
	 * from the demo keystore and posted to http://localhost:9999 where the IAIK
	 * OCSP demo {@link demo.x509.ocsp.OCSPServer server} is assumed to listen.
	 * 
	 * @param argv
	 *          responder URL and target cert file or <code>null</code> if
	 *          connecting to localhost and reading target certs from the keystore
	 */
	public void start(String[] argv)
	    throws OCSPException
	{
		try {

			if ((argv != null) && (argv.length > 0)) {
				if ((argv.length >= 2) && (argv.length <= 5)) {
					responderUrl = argv[0];
					// read in target certs
					try {
						if ((argv.length == 3) || (argv.length == 5)) {
							// target cert and its issuer cert in two files
							targetCerts_ = new X509Certificate[2];
							byte[] enc = null;
							try {
								enc = Util.readFile(argv[1]);
								targetCerts_[0] = new X509Certificate(enc);
							} catch (Exception ex) {
								System.out.println("Error reading target cert from " + argv[1] + ": "
								    + ex.toString());
								Util.waitKey();
								System.exit(-1);
							}
							try {
								enc = Util.readFile(argv[2]);
								targetCerts_[1] = new X509Certificate(enc);
							} catch (Exception ex) {
								System.out.println("Error reading target issuer cert from " + argv[2]
								    + ": " + ex.toString());
								Util.waitKey();
								System.exit(-1);
							}
						} else {
							// get target certs in one file ==> use CertificateFactory
							CertificateFactory factory = CertificateFactory
							    .getInstance("X.509", "IAIK");
							byte[] certData = Util.readFile(argv[1]);
							InputStream is = new ByteArrayInputStream(certData);
							Collection c = factory.generateCertificates(is);
							Object[] certificates = c.toArray();

							if ((certificates != null) && (certificates.length > 0)) {

								X509Certificate[] certs = new X509Certificate[certificates.length];
								for (int i = 0; i < certificates.length; i++) {
									certs[i] = (X509Certificate) certificates[i];
								}
								if (certs.length == 1) { // self signed ?
									if (certs[0].getIssuerDN().equals(certs[0].getSubjectDN())) {
										targetCerts_ = new X509Certificate[2];
										targetCerts_[0] = certs[0];
										targetCerts_[1] = certs[0];
									} else {
										System.out.println("Cert file " + argv[1]
										    + " only contains one certificate which is not self-signed.");
										System.out.println("Need issuer cert for building CertID!");
										Util.waitKey();
										System.exit(-1);
									}
								} else {
									// try to arrange the certificate chain to have target cert at
									// index 0
									targetCerts_ = Util.arrangeCertificateChain(certs, false);
									if (targetCerts_ == null) {
										targetCerts_ = certs;
									}
								}

							} else {
								System.out.println("Cert file " + argv[1]
								    + " does not contain any certificates.");
								Util.waitKey();
								System.exit(-1);
							}
						}
						// calculate the certID new for the target cert read in
						// hash algorithm for CertID
						AlgorithmID hashAlgorithm = AlgorithmID.sha1;
						try {
							reqCert_ = createReqCert(targetCerts_, hashAlgorithm);
						} catch (Exception ex) {
							throw new OCSPException("Cannot create ReqCert: " + ex.toString());
						}
						if ((argv.length == 4) || (argv.length == 5)) {
							String fileName = (argv.length == 4) ? argv[2] : argv[3];
							String pwd = (argv.length == 4) ? argv[3] : argv[4];
							System.out.println("Reading requestor key from PKCS#12 file " + fileName
							    + "...");
							readPKCS12File(fileName, pwd.toCharArray());
							signatureAlgorithm_ = AlgorithmID.sha1WithRSAEncryption;
							if (!(requestorKey_ instanceof java.security.interfaces.RSAPrivateKey)) {
								if (requestorKey_ instanceof java.security.interfaces.DSAPrivateKey) {
									signatureAlgorithm_ = AlgorithmID.dsaWithSHA1;
								} else {
									System.out.println("Error in initialization. Unknown key algorithm: "
									    + requestorKey_.getAlgorithm());
									Util.waitKey();
									System.exit(-1);
								}
							}

						} else {
							// unsigned request
							requestorKey_ = null;
							requestorCerts_ = null;
						}
						// disable trusted responder check for this demo
						trustedResponders_ = null;
					} catch (Exception ex) {
						System.out.println("Error reading target certs from " + argv[1]);
						ex.printStackTrace();
						Util.waitKey();
						System.exit(-1);
					}
				} else {
					System.out
					    .println("Usage: HttpOCSPClient [<responder url> <target certs file> [<requestor key (PKCS12)> <password>]]");
					System.out.println("or:");
					System.out
					    .println("Usage: HttpOCSPClient [<responder url> <target cert file> <target issuer cert file> [<requestor key (PKCS12)> <password>]]");
					System.out.println("\nExamples:");
					System.out.println("HttpOCSPClient http://ocspdemo.iaik.at John_TestUser.p7c");
					System.out
					    .println("HttpOCSPClient http://ocspdemo.iaik.at John_TestUser.der TestCa.der");
					Util.waitKey();
					System.exit(-1);
				}
			} else {
				// internal OCSP client-server demo
				init();
			}

			if (requestorKey_ == null) {
				System.out.println("Creating unsigned OCSP request");
			} else {
				System.out.println("Creating signed OCSP request");
			}
			boolean includeExtensions = false;
			OCSPRequest ocspRequest = createOCSPRequest(requestorKey_, requestorCerts_,
			    includeExtensions);
			System.out.println();
			System.out.println(iaik.utils.Util.toPemString(ocspRequest.getEncoded(),
			    "OCSP REQUEST"));
			// send request
			System.out.println("Send request to " + responderUrl);
			URL url = new URL(responderUrl);
			HttpOCSPRequest httpOCSPRequest = new HttpOCSPRequest(url);
			int responseCode = httpOCSPRequest.postRequest(ocspRequest);

			// read response
			if (responseCode / 100 != 2) {
				System.out.println("Error connecting to " + responderUrl + ":");
				System.out.println(httpOCSPRequest.getResponseMessage());
			} else {
				System.out.println("Parse response: ");
				OCSPResponse ocspResponse = httpOCSPRequest.getOCSPResponse();
				System.out.println();
				System.out.println(iaik.utils.Util.toPemString(ocspResponse.getEncoded(),
				    "OCSP RESPONSE"));
				parseOCSPResponse(ocspResponse, includeExtensions);
			}
		} catch (UnknownResponseException ex) {
			System.out.println("Response successful but contains an unknown response type:");
			UnknownResponseException unknown = ex;
			System.out.println("Unknown type: " + unknown.getResponseType());
			System.out.println("ASN.1 structure:");
			System.out.println(unknown.getUnknownResponse().toString());
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * Reads a PKCS12 object from the given file.
	 * 
	 * @param fileName
	 *          the name of the PKCS#12 file
	 * @param password
	 *          the password to be used for decryption
	 */
	private void readPKCS12File(String fileName, char[] password) {
		InputStream is = null;
		PKCS12 pkcs12 = null;
		try {
			is = new FileInputStream(fileName);
			pkcs12 = new PKCS12(new ASN1InputStream(is));
			if (!pkcs12.verify(password)) {
				System.out.println("Cannot read PKCS12 object: MAC verification error!");
				Util.waitKey();
				System.exit(-1);
			}
			pkcs12.decrypt(password);

			// get the requestor key
			KeyBag kB = pkcs12.getKeyBag();
			requestorKey_ = kB.getPrivateKey();

			// get the requestor certs
			CertificateBag[] certBag = pkcs12.getCertificateBags();
			java.security.cert.Certificate[] certChain = CertificateBag
			    .getCertificates(certBag);
			try {
				requestorCerts_ = Util.convertCertificateChain(certChain);
			} catch (Exception ex) {
				System.out.println("Error reading certificates from PKCS#12 file:");
				ex.printStackTrace();
				Util.waitKey();
				System.exit(-1);
			}
			requestorCerts_ = Util.arrangeCertificateChain(requestorCerts_, false);
			if (requestorCerts_ == null) {
				System.out.println("Cannot sort certificates included in PKCS#12 object!");
				Util.waitKey();
				System.exit(-1);
			}
			if (requestorKey_ == null) {
				System.out.println("Cannot create client. Missing requestor key!");
				Util.waitKey();
				System.exit(-1);
			}
			if ((requestorCerts_ == null) || (requestorCerts_.length < 1)) {
				System.out.println("Cannot create client. Missing requestor certs!");
				Util.waitKey();
				System.exit(-1);
			}

		} catch (Exception ex) {
			System.out.println("Error reading PKCS12 file " + fileName + ":");
			ex.printStackTrace();
			Util.waitKey();
			System.exit(-1);
		} finally {
			if (is != null) {
				try {
					is.close();
				} catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * The main method. Starts the client.
	 * 
	 * @param argv
	 *          responder URL and target cert file or <code>null</code> if
	 *          connecting to localhost and reading target certs from the keystore
	 * @exception Exception
	 *              if an error occurs when reading required keys and certificates
	 *              from files
	 */
	public static void main(String argv[])
	    throws Exception
	{

		Security.insertProviderAt(new IAIK(), 1);
		try {
			// install IAIK_ECC provider, if available
			Class eccProviderClass = Class.forName("iaik.security.ecc.provider.ECCProvider");
			Provider eccProvider = (Provider) eccProviderClass.newInstance();
			Security.insertProviderAt(eccProvider, 2);
		} catch (Exception ex) {
			// ignore; ECC provider not available
		}

		(new HttpOCSPClient()).start(argv);
		System.out.println("Ready!");
		Util.waitKey();
	}

}
