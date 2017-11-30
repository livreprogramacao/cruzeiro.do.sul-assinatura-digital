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

import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.DistributionPoint;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.x509.RevokedCertificate;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.CRLNumber;
import iaik.x509.extensions.CertificateIssuer;
import iaik.x509.extensions.HoldInstructionCode;
import iaik.x509.extensions.InvalidityDate;
import iaik.x509.extensions.IssuingDistributionPoint;
import iaik.x509.extensions.ReasonCode;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.GregorianCalendar;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class tests the implemented X509v2 CRL extensions.
 * <p>
 * The following X509v2 CRL (entry) extensions are implemented (and tested by this class):
 * <ul>
 * <li> CRLNumber
 * <li> CertificateIssuer
 * <li> IssuingDistributionPoint
 * <li> ReasonCode
 * <li> HoldInstructionCode
 * <li> InvaladityDate
 * </ul>
 * <p>
 * Issuer and issuer private key are read in from a keystore "jce.keystore" located
 * in the current working directory (if it yet not does exist, please run {@link
 * demo.keystore.SetupKeyStore SetupKeyStore} for creating it.
 *
 * @version File Revision <!-- $$Revision: --> 22 <!-- $ -->
 */
public class CRLExtensions implements IAIKDemo {

	/**
	 * Creates a new CRL and adds the <code>CRLNumber</code> and <code>ReasonCode</code>
	 * extensions.
	 * <p>
	 * Similary to the private key and the issuer two certificates to be revoked read in 
	 * from the keystore.
	 */
	public void start() {

		try {
			X509Certificate issuer_cert = IaikKeyStore.getCaCertificate(IaikKeyStore.RSA);
			PrivateKey private_key = IaikKeyStore.getCaPrivateKey(IaikKeyStore.RSA);

			GregorianCalendar gc = new GregorianCalendar();

			X509Certificate cert1 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_1024)[0];
			RevokedCertificate rc1 = new RevokedCertificate(cert1, gc.getTime());
			X509Certificate cert2 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_2048)[0];
			RevokedCertificate rc2 = new RevokedCertificate(cert2, gc.getTime());

			// first create the extensions of the revoked certificates

			// ReasonCode
			rc1.addExtension(new ReasonCode(ReasonCode.keyCompromise));
			rc2.addExtension(new ReasonCode(ReasonCode.certificateHold));

			// HoldInstructionCode
			rc2.addExtension(new HoldInstructionCode(
			    HoldInstructionCode.holdInstructionCallIssuer));

			// InvaladityDate
			GregorianCalendar date = new GregorianCalendar();
			date.add(Calendar.DATE, -1);
			rc2.addExtension(new InvalidityDate(date.getTime()));

			// CertificateIssuer (only for testing; if CRL and certificae issuer are the
			// same this extension has not to be present
			Name certIssuer = (Name) cert2.getIssuerDN();
			CertificateIssuer certificateIssuer = new CertificateIssuer(new GeneralNames(
			    new GeneralName(GeneralName.directoryName, certIssuer)));
			certificateIssuer.setCritical(true);
			rc2.addExtension(certificateIssuer);

			X509CRL crl = new X509CRL();

			crl.setIssuerDN(issuer_cert.getSubjectDN());

			crl.setThisUpdate(gc.getTime());
			gc.add(Calendar.WEEK_OF_YEAR, 1);
			crl.setNextUpdate(gc.getTime());
			crl.setSignatureAlgorithm(AlgorithmID.sha1WithRSAEncryption);

			crl.addCertificate(rc1);
			crl.addCertificate(rc2);

			// AuthorityKeyIdentifier
			AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
			authorityKeyIdentifier.setKeyIdentifier(new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1 });
			GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier,
			    "http://ca.test.com/");
			authorityKeyIdentifier.setAuthorityCertIssuer(new GeneralNames(generalName));
			authorityKeyIdentifier.setAuthorityCertSerialNumber(new BigInteger("91698236"));
			crl.addExtension(authorityKeyIdentifier);

			// CRLNumber
			CRLNumber cRLNumber = new CRLNumber(BigInteger.valueOf(4234234));
			crl.addExtension(cRLNumber);

			// IssuingDistributionPoint
			GeneralNames distributionPointName = new GeneralNames(new GeneralName(
			    GeneralName.uniformResourceIdentifier, "http://ca.iaik.com/crl/"));
			IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
			issuingDistributionPoint.setDistributionPointName(distributionPointName);
			issuingDistributionPoint.setCritical(true);
			issuingDistributionPoint.setOnlyContainsUserCerts(true);
			issuingDistributionPoint.setIndirectCRL(true);
			issuingDistributionPoint.setReasonFlags(DistributionPoint.keyCompromise
			    | DistributionPoint.certificateHold | DistributionPoint.cessationOfOperation);
			crl.addExtension(issuingDistributionPoint);

			crl.sign(private_key);

			byte[] test = crl.toByteArray();
			// send CRL to ...
			//      iaik.utils.Util.saveToFile(test,"test_data/crls/testCRL.crl");

			// receive CRL
			X509CRL new_crl = new X509CRL(test);
			System.out.println(new_crl.toString(true));

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the CRLExtensions demo.
	 */
	public static void main(String[] argv)
	    throws IOException
	{

		DemoUtil.initDemos();
		(new CRLExtensions()).start();
		System.in.read();
	}
}
