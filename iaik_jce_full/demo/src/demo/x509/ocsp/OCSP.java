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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AccessDescription;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.Name;
import iaik.security.provider.IAIK;
import iaik.security.random.SecRandom;
import iaik.utils.CryptoUtils;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.ExtendedKeyUsage;
import iaik.x509.ocsp.BasicOCSPResponse;
import iaik.x509.ocsp.CertID;
import iaik.x509.ocsp.CertStatus;
import iaik.x509.ocsp.OCSPException;
import iaik.x509.ocsp.OCSPRequest;
import iaik.x509.ocsp.OCSPResponse;
import iaik.x509.ocsp.ReqCert;
import iaik.x509.ocsp.Request;
import iaik.x509.ocsp.ResponderID;
import iaik.x509.ocsp.SingleResponse;
import iaik.x509.ocsp.UnknownInfo;
import iaik.x509.ocsp.UnknownResponseException;
import iaik.x509.ocsp.extensions.CrlID;
import iaik.x509.ocsp.extensions.Nonce;
import iaik.x509.ocsp.extensions.ServiceLocator;
import iaik.x509.ocsp.utils.TrustedResponders;

/**
 * Tests the OCSP implementation.
 * <p>
 * This class demonstrates the usage of the IAIK ocsp implementation by
 * simulating the following actions in the given order:
 * <ol>
 * <li>Requestor: creation and encoding of an ocsp request
 * <li>Responder: decoding and parsing of the ocsp request
 * <li>Responder: creation and encoding of an ocsp response for the given
 * request without crl
 * <li>Requestor: decoding, parsing, and verification of the response
 * </ol>
 * The test sequence above is performed four times to simulate unsigned requests
 * with and without extensions, and signed requests with and without extensions.
 * <p>
 * The keys and certificates required for this demo are obtained from the
 * IAIK-JCE demo keystore "jce.keystore" which may be generated by running the
 * {@link demo.keystore.SetupKeyStore SetupKeyStore} program.
 * 
 * @version File Revision <!-- $$Revision: --> 31 <!-- $ -->
 */
public class OCSP implements IAIKDemo {

	/**
	 * Calculates an ReqCert of type <code>certID</code> from the given target
	 * certificates.
	 * 
	 * @param targetCerts
	 *          the target certificate chain containing the target certificate
	 *          (for which OCSP status information is requested) at index 0
	 * @param hashAlgorithm
	 *          the hash algorithm to be used
	 * 
	 * @return the ReqCert
	 * 
	 * @throws Exception
	 *           if an exception occurs
	 */
	final static ReqCert createReqCert(X509Certificate[] targetCerts,
	                                   AlgorithmID hashAlgorithm)
	    throws Exception
	{

		if ((targetCerts == null) || (targetCerts.length == 0)) {
			throw new NullPointerException("targetCerts must not be null!");
		}
		if (hashAlgorithm == null) {
			throw new NullPointerException("hashAlgorithm must not be null!");
		}

		// calculate certID

		// issuer name
		Name issuerName = (Name) targetCerts[1].getSubjectDN();
		// issuer key
		PublicKey issuerKey = targetCerts[1].getPublicKey();
		// create the certID
		try {
			CertID certID = new CertID(hashAlgorithm, issuerName, issuerKey,
			    targetCerts[0].getSerialNumber());
			return new ReqCert(ReqCert.certID, certID);
		} catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException("No implementation for SHA!");
		}

	}

	// private key of the requestor
	PrivateKey requestorKey_;

	// private key of responder
	PrivateKey responderKey_;

	// the signing certs of the requestor
	X509Certificate[] requestorCerts_;
	// the signing certs of the responder
	X509Certificate[] responderCerts_;

	// the target certs for which to get status information
	X509Certificate[] targetCerts_;

	// the signature algorithm
	AlgorithmID signatureAlgorithm_;

	// hash algorithm for CertID
	AlgorithmID hashAlgorithm_;

	// secure random number generator
	SecureRandom random_;
	// the reqCert of the target cert
	ReqCert reqCert_;
	// a nonce value
	byte[] nonce_;

	// trust repository for responders
	TrustedResponders trustedResponders_;

	/**
	 * Setup the demo certificate chains.
	 * 
	 * Keys and certificates are retrieved from the demo KeyStore.
	 * 
	 * @exception IOException
	 *              if a file read error occurs
	 */
	public OCSP() {
		random_ = SecRandom.getDefault();
		// defaults
		signatureAlgorithm_ = AlgorithmID.sha1WithRSAEncryption;
		hashAlgorithm_ = AlgorithmID.sha1;
	}

	/**
	 * Inits key, certificates; creates cert id.
	 * 
	 * @exception if
	 *              an error occurs during initialization
	 */
	protected void init()
	    throws Exception
	{
		// add all certificates to the list
		requestorCerts_ = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
		    IaikKeyStore.SZ_1024);
		requestorKey_ = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
		responderCerts_ = new X509Certificate[] { IaikKeyStore
		    .getCaCertificate(IaikKeyStore.RSA) };
		responderKey_ = IaikKeyStore.getCaPrivateKey(IaikKeyStore.RSA);
		targetCerts_ = IaikKeyStore
		    .getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_512);

		// calculate certID
		// create the certID
		reqCert_ = createReqCert(targetCerts_, hashAlgorithm_);

		// we want to trust our responder for signing responses for certs issued by
		// targetCerts[1]
		ResponderID responderID = new ResponderID((Name) responderCerts_[0].getSubjectDN());
		trustedResponders_ = new TrustedResponders();
		trustedResponders_.addTrustedResponderEntry(responderID, targetCerts_[1]);

		signatureAlgorithm_ = AlgorithmID.sha1WithRSAEncryption;

	}

	/**
	 * Performs three tests:
	 * <ol>
	 * <li>Unsigned request without extensions.
	 * <li>Unsigned request with extensions.
	 * <li>Signed request without extensions.
	 * <li>Signed request with extensions.
	 * </ol>
	 */
	public void start() {
		try {
			init();
			OCSPRequest ocspRequest = null;
			OCSPResponse ocspResponse = null;
			ByteArrayInputStream encodedStream = null;
			byte[] response = null;
			// include extensions in request?
			boolean includeExtensions = false;

			// 1. Unsigned request without extensions
			System.out.println("Requestor: Creates an unsigned request without extensions.");
			ocspRequest = createOCSPRequest(null, null, false);
			System.out.println("Responder: Parses request and sends response");
			encodedStream = new ByteArrayInputStream(ocspRequest.getEncoded());
			response = createOCSPResponse(encodedStream, null, includeExtensions);
			System.out.println("Requestor: Parses response");
			// decode
			ocspResponse = new OCSPResponse(response);
			parseOCSPResponse(ocspResponse, includeExtensions);
			System.out.println("\n----------------------\n");

			// 2. Unsigned request with extensions
			includeExtensions = true;
			System.out.println("Requestor: Creates an unsigned request with extensions.");
			ocspRequest = createOCSPRequest(null, null, true);
			System.out.println("Responder: Parses request and sends response");
			encodedStream = new ByteArrayInputStream(ocspRequest.getEncoded());
			response = createOCSPResponse(encodedStream, null, includeExtensions);
			System.out.println("Requestor: Parses response");
			// decode
			ocspResponse = new OCSPResponse(response);
			parseOCSPResponse(ocspResponse, includeExtensions);
			System.out.println("\n----------------------\n");

			// 3. Signed request without extensions
			includeExtensions = false;
			System.out.println("Requestor: Creates an signed request without extensions.");
			ocspRequest = createOCSPRequest(requestorKey_, requestorCerts_, false);
			System.out.println("Responder: Parses request and sends response");
			encodedStream = new ByteArrayInputStream(ocspRequest.getEncoded());
			response = createOCSPResponse(encodedStream, null, includeExtensions);
			System.out.println("Requestor: Parses response");
			// decode
			ocspResponse = new OCSPResponse(response);
			parseOCSPResponse(ocspResponse, includeExtensions);
			System.out.println("\n----------------------\n");

			// 4. Signed request with extensions
			includeExtensions = true;
			System.out.println("Requestor: Creates an signed request with extensions.");
			ocspRequest = createOCSPRequest(requestorKey_, requestorCerts_, true);
			System.out.println("Responder: Parses request and sends response");
			encodedStream = new ByteArrayInputStream(ocspRequest.getEncoded());
			response = createOCSPResponse(encodedStream, null, includeExtensions);
			System.out.println("Requestor: Parses response");
			// decode
			ocspResponse = new OCSPResponse(response);
			parseOCSPResponse(ocspResponse, includeExtensions);
			System.out.println("\n\n");

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Creates an OCSPRequest.
	 * 
	 * @param requestorKey
	 *          the private key of the requestor, or <code>null</code> if the
	 *          request shall not be signed
	 * @param requestorCerts
	 *          if the request shall be signed (requestorKey != null) and signer
	 *          certs shall be included
	 * @param includeExtensions
	 *          if extensions shall be included
	 * 
	 * @return the OCSPRequest created
	 * 
	 * @exception OCSPException
	 *              if an error occurs when creating the request
	 */
	public OCSPRequest createOCSPRequest(PrivateKey requestorKey,
	                                     X509Certificate[] requestorCerts,
	                                     boolean includeExtensions)
	    throws OCSPException
	{

		return createOCSPRequest(requestorKey, requestorCerts, targetCerts_,
		    includeExtensions);
	}

	/**
	 * Creates an OCSPRequest.
	 * 
	 * @param requestorKey
	 *          the private key of the requestor, or <code>null</code> if the
	 *          request shall not be signed
	 * @param requestorCerts
	 *          if the request shall be signed (requestorKey != null) and signer
	 *          certs shall be included
	 * @param targetCerts
	 *          the certs for which status information shall be included
	 * @param includeExtensions
	 *          if extensions shall be included
	 * 
	 * @return the OCSPRequest created
	 * 
	 * @exception OCSPException
	 *              if an error occurs when creating the request
	 */
	public OCSPRequest createOCSPRequest(PrivateKey requestorKey,
	                                     X509Certificate[] requestorCerts,
	                                     X509Certificate[] targetCerts,
	                                     boolean includeExtensions)
	    throws OCSPException
	{

		if (targetCerts != null) {
			targetCerts_ = (X509Certificate[]) targetCerts.clone();
			try {
				reqCert_ = createReqCert(targetCerts, hashAlgorithm_);
			} catch (Exception ex) {
				throw new OCSPException("Error creating cert id: " + ex.toString());
			}
		}

		if (reqCert_ == null) {
			throw new OCSPException("Cannot create ocsp request from null cert id!");
		}

		try {

			// create a single request for the target cert identified by the reqCert
			Request request = new Request(reqCert_);

			if (includeExtensions) {
				if (responderCerts_ != null) {
					// include service locator
					ObjectID accessMethod = ObjectID.caIssuers;
					GeneralName accessLocation = new GeneralName(
					    GeneralName.uniformResourceIdentifier, "http://www.testResponder.at");
					AccessDescription accessDescription = new AccessDescription(accessMethod,
					    accessLocation);
					AuthorityInfoAccess locator = new AuthorityInfoAccess(accessDescription);
					ServiceLocator serviceLocator = new ServiceLocator(
					    (Name) responderCerts_[0].getSubjectDN());
					serviceLocator.setLocator(locator);
					request.setServiceLocator(serviceLocator);
				}
			}

			// create the OCSPRequest
			OCSPRequest ocspRequest = new OCSPRequest();

			// set the requestList
			ocspRequest.setRequestList(new Request[] { request });

			if (includeExtensions) {
				// we only accept basic OCSP responses
				ocspRequest
				    .setAcceptableResponseTypes(new ObjectID[] { BasicOCSPResponse.responseType });

				// set a nonce value
				nonce_ = new byte[16];
				random_.nextBytes(nonce_);
				ocspRequest.setNonce(nonce_);
			}

			if (requestorKey != null) {
				if ((requestorCerts == null) || (requestorCerts.length == 0)) {
					throw new NullPointerException(
					    "Requestor certs must not be null if request has to be signed!");
				}
				// set the requestor name
				ocspRequest.setRequestorName(new GeneralName(GeneralName.directoryName,
				    requestorCerts[0].getSubjectDN()));
				// include signing certificates
				ocspRequest.setCertificates(requestorCerts);
				// sign the request
				ocspRequest.sign(signatureAlgorithm_, requestorKey);
			}
			System.out.println("Request created:");
			System.out.println(ocspRequest.toString(true));

			return ocspRequest;

		} catch (Exception ex) {
			throw new OCSPException(ex.toString());
		}

	}

	/**
	 * Creates an ocsp response answering the given ocsp request.
	 * 
	 * @param is
	 *          the encoded OCSP request supplied from an input stream
	 * @param requestorKey
	 *          the signing key of the requestor (may be supplied for allowing to
	 *          verify a signed request with no certificates included)
	 * @param includeExtensions
	 *          if extensions shall be included
	 * 
	 * @return the DER encoded OCSPResponse
	 */
	public byte[] createOCSPResponse(InputStream is,
	                                 PublicKey requestorKey,
	                                 boolean includeExtensions)/* throws OCSPException */
	{

		OCSPResponse ocspResponse = null;
		OCSPRequest ocspRequest = null;

		// first parse the request
		int responseStatus = OCSPResponse.successful;
		System.out.println("Parsing request...");

		try {
			ocspRequest = new OCSPRequest(is);
			if (ocspRequest.containsSignature()) {
				System.out.println("Request is signed.");

				boolean signatureOk = false;
				if (requestorKey != null) {
					System.out.println("Verifying signature using supplied requestor key.");
					try {
						ocspRequest.verify(requestorKey);
						signatureOk = true;
						System.out.println("Signature ok");

					} catch (Exception ex) {
						// ignore
					}
				}
				if (!signatureOk && ocspRequest.containsCertificates()) {
					System.out.println("Verifying signature with included signer cert...");

					X509Certificate signerCert = ocspRequest.verify();
					System.out.println("Signature ok from request signer "
					    + signerCert.getSubjectDN());
					signatureOk = true;
				}
				if (!signatureOk) {
					System.out
					    .println("Request signed but cannot verify signature since missing signer key. Sending malformed request!");
					responseStatus = OCSPResponse.malformedRequest;
				}
			} else {
				System.out.println("Unsigned request!");
			}

		} catch (IOException ex) {
			System.out.println("Encoding error; sending malformedRequest " + ex.getMessage());
			responseStatus = OCSPResponse.malformedRequest;
		} catch (NoSuchAlgorithmException ex) {
			System.out.println("Cannot verify; sending internalError: " + ex.getMessage());
			responseStatus = OCSPResponse.internalError;
		} catch (OCSPException ex) {
			System.out
			    .println("Included certs do not belong to signer; sending malformedRequest : "
			        + ex.getMessage());
			responseStatus = OCSPResponse.malformedRequest;
		} catch (InvalidKeyException ex) {
			System.out.println("Signer key invalid; sending malformedRequest : "
			    + ex.getMessage());
			responseStatus = OCSPResponse.malformedRequest;
		} catch (SignatureException ex) {
			System.out.println("Signature verification error; sending malformedRequest : "
			    + ex.getMessage());
			responseStatus = OCSPResponse.malformedRequest;
		} catch (Exception ex) {
			ex.printStackTrace();
			System.out
			    .println("Some error occured during request parsing/verification; sending tryLater "
			        + ex.getMessage());
			responseStatus = OCSPResponse.tryLater;
		}
		if (responseStatus != OCSPResponse.successful) {
			ocspResponse = new OCSPResponse(responseStatus);
			return ocspResponse.getEncoded();
		}

		try {
			// does client understand Basic OCSP response type?
			ObjectID[] accepatablResponseTypes = ocspRequest.getAccepatableResponseTypes();
			if ((accepatablResponseTypes != null) && (accepatablResponseTypes.length > 0)) {
				boolean supportsBasic = false;
				for (int i = 0; i < accepatablResponseTypes.length; i++) {
					if (accepatablResponseTypes[i].equals(BasicOCSPResponse.responseType)) {
						supportsBasic = true;
						break;
					}
				}
				if (!supportsBasic) {
					// what to do if client does not support basic OCSP response type??
					// we send an basic response anyway, since there seems to be no proper
					// status message
					System.out
					    .println("Warning! Client does not support basic response type. Using it anyway...");
				}
			}
		} catch (Exception ex) {
			// ignore this
		}
		// successfull
		ocspResponse = new OCSPResponse(OCSPResponse.successful);
		// now we build the basic ocsp response
		BasicOCSPResponse basicOCSPResponse = new BasicOCSPResponse();

		try {
			// responder ID
			ResponderID responderID = new ResponderID((Name) responderCerts_[0].getSubjectDN());
			basicOCSPResponse.setResponderID(responderID);

			GregorianCalendar date = new GregorianCalendar();
			// producedAt date
			Date producedAt = date.getTime();
			basicOCSPResponse.setProducedAt(producedAt);

			// thisUpdate date
			Date thisUpdate = date.getTime();
			// nextUpdate date
			date.add(Calendar.MONTH, 1);
			Date nextUpdate = date.getTime();
			// archiveCutoff
			date.add(Calendar.YEAR, -3);
			Date archivCutoffDate = date.getTime();

			// create the single responses for requests included
			Request[] requests = ocspRequest.getRequestList();
			SingleResponse[] singleResponses = new SingleResponse[requests.length];

			for (int i = 0; i < requests.length; i++) {
				Request request = requests[i];
				CertStatus certStatus = null;
				// check the service locator
				ServiceLocator serviceLocator = request.getServiceLocator();
				if (serviceLocator != null) {
					System.out.println("Request No. " + i
					    + " contains the ServiceLocator extension:");
					System.out.println(serviceLocator + "\n");

					Name issuer = serviceLocator.getIssuer();
					if (!issuer.equals(responderCerts_[0].getSubjectDN())) {
						// client does not trust our responder; but we are not able to
						// forward it
						// --> CertStatus unknown
						certStatus = new CertStatus(new UnknownInfo());
					}
				}
				if (certStatus == null) {
					// here now the server checks the status of the cert
					// we only can give information about one cert
					if (request.getReqCert().isReqCertFor(targetCerts_[0], targetCerts_[1], null)) {
						// we assume "good" here
						certStatus = new CertStatus();
					} else {
						certStatus = new CertStatus(new UnknownInfo());
					}
				}
				singleResponses[i] = new SingleResponse(request.getReqCert(), certStatus,
				    thisUpdate);
				singleResponses[i].setNextUpdate(nextUpdate);

				if (includeExtensions) {
					singleResponses[i].setArchiveCutoff(archivCutoffDate);
					CrlID crlID = new CrlID();
					crlID.setCrlUrl("http://www.testResponder.at/clrs/crl1.crl");
					singleResponses[i].setCrlID(crlID);
				}

			}
			// set the single responses
			basicOCSPResponse.setSingleResponses(singleResponses);

		} catch (Exception ex) {
			ex.printStackTrace();

			System.out.println("Some error occured; sending tryLater " + ex.getMessage());
			return (new OCSPResponse(OCSPResponse.tryLater)).getEncoded();

		}

		try {
			// Nonce included?
			Nonce nonce = (Nonce) ocspRequest.getExtension(Nonce.oid);
			if (nonce != null) {
				basicOCSPResponse.addExtension(nonce);
			}
		} catch (Exception ex) {
			// can only ignore this
			System.out.println("Error in setting Nonce for response (ignore this): "
			    + ex.getMessage());
		}

		// sign the response
		basicOCSPResponse.setCertificates(responderCerts_);
		try {
			basicOCSPResponse.sign(signatureAlgorithm_, responderKey_);
		} catch (Exception ex) {
			System.out.println("Error signing response: " + ex.getMessage());
			System.out.println("Send tryLater response");
			return (new OCSPResponse(OCSPResponse.tryLater)).getEncoded();
		}

		ocspResponse.setResponse(basicOCSPResponse);
		return ocspResponse.getEncoded();

	}

	/**
	 * Parses an ocsp response received and looks for the single responses
	 * included.
	 * 
	 * @param ocspResponse
	 *          the OCSP response
	 * @param includeExtensions
	 *          whether there have been extensions included in the request and
	 *          therefore have to be checked now (Nonce)
	 * 
	 * @exception OCSPException
	 *              if an error occurs when creating the response
	 */
	public void parseOCSPResponse(OCSPResponse ocspResponse, boolean includeExtensions)
	    throws OCSPException
	{

		try {

			// get the response status:
			int responseStatus = ocspResponse.getResponseStatus();
			if (responseStatus != OCSPResponse.successful) {
				System.out.println("Not successful; got response status: "
				    + ocspResponse.getResponseStatusName());
				return;
			}
			// response successful
			System.out.println("Succesful OCSP response:");
			System.out.println(ocspResponse.toString());

			// get the basic ocsp response (the only type we support; otherwise an
			// UnknownResponseException would have been thrown during parsing the
			// response
			BasicOCSPResponse basicOCSPResponse = (BasicOCSPResponse) ocspResponse
			    .getResponse();

			// we verify the response
			try {
				if (basicOCSPResponse.containsCertificates()) {
					X509Certificate signerCert = basicOCSPResponse.verify();
					System.out.println("Signature ok from response signer "
					    + signerCert.getSubjectDN());

					// trusted responder?
					if (!signerCert.equals(targetCerts_[1])) {
						// authorized for signing
						ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage) signerCert
						    .getExtension(ExtendedKeyUsage.oid);
						boolean ocspSigning = false;
						if (extendedKeyUsage != null) {
							ObjectID[] purposes = extendedKeyUsage.getKeyPurposeIDs();
							for (int i = 0; i < purposes.length; i++) {
								if (purposes[i].equals(ExtendedKeyUsage.ocspSigning)) {
									ocspSigning = true;
									break;
								}
							}
						}
						if (trustedResponders_ != null) {
							if (!(ocspSigning && trustedResponders_.isTrustedResponder(
							    basicOCSPResponse.getResponderID(), signerCert, targetCerts_[1]))) {
								System.out.println("WARNING: Responder not trusted! Reject response!!!");
							}
						} else {
							if (ocspSigning) {
								if (signerCert.getIssuerDN().equals(targetCerts_[1].getSubjectDN())) {
									System.out
									    .println("WARNING: Responder authorized by target cert issuer, but no trust information available!");
								} else {
									System.out
									    .println("WARNING: Responder cert has ocspSigning ExtendedKeyUsage, but is not issued by target cert issuer!");
								}
							} else {
								System.out
								    .println("WARNING: Responder not equal to target cert issuer and not authorized for OCSP signing!");
							}
						}
					}
				} else {
					System.out
					    .println("Certificates not included; try to verify with issuer target cert...");
					basicOCSPResponse.verify(targetCerts_[1].getPublicKey());
					System.out.println("Signature ok!");
				}
			} catch (SignatureException ex) {
				System.out.println("Signature verification error!!!");
			}

			System.out.println("Response produced at :" + basicOCSPResponse.getProducedAt());

			ResponderID responderID = basicOCSPResponse.getResponderID();
			System.out.println("ResponderID: " + responderID);

			// look if we got an answer for our request:
			SingleResponse singleResponse = null;
			try {
				singleResponse = basicOCSPResponse.getSingleResponse(reqCert_);
			} catch (OCSPException ex) {
				System.out.println(ex.getMessage());
				System.out.println("Try again...");
				singleResponse = basicOCSPResponse.getSingleResponse(targetCerts_[0],
				    targetCerts_[1], null);
			}

			if (singleResponse != null) {
				System.out.println("Status information got for cert: ");
				System.out.println(singleResponse.getCertStatus());
				System.out.println("This Update: " + singleResponse.getThisUpdate());
				Date now = new Date();
				// next update included?
				Date nextUpdate = singleResponse.getNextUpdate();
				if (nextUpdate != null) {
					System.out.println("Next Update: " + nextUpdate);
					if (nextUpdate.before(now)) {
						System.out
						    .println("WARNING: There must be more recent information available!");
					}
				}
				// check thisUpdate date
				Date thisUpdate = singleResponse.getThisUpdate();
				if (thisUpdate == null) {
					System.out.println("Error: Missing thisUpdate information!");
				} else {
					if (thisUpdate.after(now)) {
						System.out
						    .println("WARNING: Response yet not valid! thisUpdate (" + thisUpdate
						        + ") is somewhere in future (current date is: " + now + ")!");
					}
				}
				// archive cutoff included?
				Date archiveCutoffDate = singleResponse.getArchiveCutoff();
				if (archiveCutoffDate != null) {
					System.out.println("archivCutoffDate: " + archiveCutoffDate);
				}
				// crl id included?
				CrlID crlID = singleResponse.getCrlID();
				if (crlID != null) {
					System.out.println("crlID: " + crlID);
				}
			} else {
				System.out.println("No response got for our request!");
			}

			// nonce check
			byte[] respondedNonce = basicOCSPResponse.getNonce();
			if (respondedNonce != null) {
				if (!CryptoUtils.secureEqualsBlock(nonce_, respondedNonce)) {
					System.out.println("Error!!! Nonce values do not match!");
				}
			} else {
				if ((includeExtensions == true) && (nonce_ != null)) {
					System.out.println("Error!!! Nonce not returned in server response!");
				}
			}

		} catch (UnknownResponseException ex) {
			System.out
			    .println("This response is successful but contains an unknown response type:");
			UnknownResponseException unknown = ex;
			System.out.println("Unknown type: " + unknown.getResponseType());
			System.out.println("ASN.1 structure:");
			System.out.println(unknown.getUnknownResponse().toString());
		} catch (NoSuchAlgorithmException ex) {
			throw new OCSPException("Error while verifying signature: " + ex.getMessage());
		} catch (InvalidKeyException ex) {
			throw new OCSPException("Error while verifying signature: " + ex.getMessage());
		} catch (Exception ex) {
			throw new OCSPException(ex.getMessage());
		}
	}

	/**
	 * Starts the test.
	 * 
	 * @exception Exception
	 *              if an error occurs when reading required keys and certificates
	 *              from files
	 */
	public static void main(String argv[])
	    throws Exception
	{

		Security.insertProviderAt(new IAIK(), 2);
		OCSP ocsp = new OCSP();
		ocsp.start();
		System.in.read();
	}
}
