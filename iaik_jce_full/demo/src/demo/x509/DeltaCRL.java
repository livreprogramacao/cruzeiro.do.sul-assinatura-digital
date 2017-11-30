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
import iaik.x509.RevokedCertificate;
import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.CRLNumber;
import iaik.x509.extensions.DeltaCRLIndicator;
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
 * This class tests the implemented DeltaCRL.
 * <p>
 * The following X509v2 CRL (entry) extensions are implemented (and tested by this class):
 * <ul>
 * <li> CRLNumber
 * <li> CertificateIssuer
 * <li> DeltaCRLIndicator
 * <li> IssuingDistributionPoint
 * <li> ReasonCode
 * </ul>
 * <p>
 * Issuer and issuer private key are read in from a keystore "jce.keystore" located
 * in the current working directory (if it yet not does exist, please run {@link
 * demo.keystore.SetupKeyStore SetupKeyStore} for creating it.
 *
 * @version File Revision <!-- $$Revision: --> 1 <!-- $ -->
 */
public class DeltaCRL implements IAIKDemo {

	/**
	 * Creates a delta CRL for the base CRL with CRL number 4234234 (CRLExtensions-Demo) 
	 * and adds the <code>CRLNumber</code> and <code>ReasonCode</code> extensions.
	 * <p>
	 * The certificates to change the status for are read in from the keystore.
	 * <p>
	 *  The issuer and the private key to sign the deltaCRL must be equal to the 
	 *  private key of the base CRL.
	 *  Also the IssuingDistributionPoints must be equal to those from the base CRL.
	 */
	public void start() {

		try {
			X509Certificate issuer_cert = IaikKeyStore.getCaCertificate(IaikKeyStore.RSA);
			PrivateKey private_key = IaikKeyStore.getCaPrivateKey(IaikKeyStore.RSA);

			GregorianCalendar gc = new GregorianCalendar();

			X509Certificate cert1 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_1024)[0];
			RevokedCertificate rc1 = new RevokedCertificate(cert1, gc.getTime());
			X509Certificate cert3 = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_512)[0];
			RevokedCertificate rc3 = new RevokedCertificate(cert3, gc.getTime());

			// first create the extensions of the revoked certificates

			// ReasonCode
			rc1.addExtension(new ReasonCode(ReasonCode.removeFromCRL));
			rc3.addExtension(new ReasonCode(ReasonCode.cessationOfOperation));

			X509CRL crl = new X509CRL();

			crl.setIssuerDN(issuer_cert.getSubjectDN());

			crl.setThisUpdate(gc.getTime());
			gc.add(Calendar.WEEK_OF_YEAR, 1);
			crl.setNextUpdate(gc.getTime());
			crl.setSignatureAlgorithm(AlgorithmID.sha1WithRSAEncryption);

			crl.addCertificate(rc1);
			crl.addCertificate(rc3);

			// AuthorityKeyIdentifier
			AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
			authorityKeyIdentifier.setKeyIdentifier(new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1 });
			GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier,
			    "http://ca.test.com/");
			authorityKeyIdentifier.setAuthorityCertIssuer(new GeneralNames(generalName));
			authorityKeyIdentifier.setAuthorityCertSerialNumber(new BigInteger("91698236"));
			crl.addExtension(authorityKeyIdentifier);

			// CRLNumber
			CRLNumber cRLNumber = new CRLNumber(BigInteger.valueOf(4234235));
			crl.addExtension(cRLNumber);

			// DeltaCRLIndicator - specifies CRL Number of base CRL
			DeltaCRLIndicator deltaCrlIndicator = new DeltaCRLIndicator(
			    BigInteger.valueOf(4234234));
			deltaCrlIndicator.setCritical(true);
			crl.addExtension(deltaCrlIndicator);

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

			System.out.println(crl.toString(true));

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the DeltaCRL demo.
	 */
	public static void main(String[] argv)
	    throws IOException
	{

		DemoUtil.initDemos();
		(new DeltaCRL()).start();
		System.in.read();
	}
}
