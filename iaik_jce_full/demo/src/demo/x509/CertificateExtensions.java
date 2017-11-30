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

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AccessDescription;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.DistributionPoint;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.GeneralSubtree;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyMapping;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.security.rsa.RSAPrivateKey;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.AuthorityInfoAccess;
import iaik.x509.extensions.AuthorityKeyIdentifier;
import iaik.x509.extensions.BasicConstraints;
import iaik.x509.extensions.CRLDistributionPoints;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.IssuerAltName;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.NameConstraints;
import iaik.x509.extensions.PolicyConstraints;
import iaik.x509.extensions.PolicyMappings;
import iaik.x509.extensions.PrivateKeyUsagePeriod;
import iaik.x509.extensions.SubjectAltName;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Vector;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class tests several implemented X509v3 certificate extensions.
 * <p>
 * The following X509v3 extensions are implemented (and tested by this class):
 * <p>
 * <ul>
 * <li>AuthorityKeyIdentifier
 * <li>BasicConstraints
 * <li>CertificatePolicies
 * <li>CRLDistributionPoints
 * <li>IssuerAltName
 * <li>KeyUsage
 * <li>NameConstraints
 * <li>PolicyConstraints
 * <li>PolicyMappings
 * <li>PrivateKeyUsagePeriod
 * <li>SubjectAltName
 * <li>SubjectKeyIdentifier
 * </ul>
 * <p>
 * To avoid the time consuming process of key creation, the issuer certificate
 * and private key are read in from a keystore "jce.keystore" located in the
 * current working directory (if it yet not does exist, please run
 * {@link demo.keystore.SetupKeyStore SetupKeyStore} for creating it.
 * 
 * @version File Revision <!-- $$Revision: --> 34 <!-- $ -->
 */
public class CertificateExtensions implements IAIKDemo {

	/**
	 * Creates a certificate according to the X.509 notation and subsequently
	 * saves the certifcate to a specified file.
	 * <p>
	 * Depending on the subject ID either a self-signed CA certificate will be
	 * created or a user certificate. If the <code>extensions</code> parameter is
	 * set to <code>true</code>, <code>SubjectKeyIdentifier</code>,
	 * <code>KeyUsage</code>, and <code>BasicConstraints</code> extensions will be
	 * added to the new certifcate.
	 * 
	 * @param subject
	 *          the user demanding the certificate (may be the certification
	 *          authority itself)
	 * @param pk
	 *          the subject's public key to be certified
	 * @param issuer
	 *          the certification authority that issues the certificate
	 * @param sk
	 *          the issuer's private key for signing the certificate
	 * @param algorithm
	 *          the ID of the signature algorithm
	 * @param fileName
	 *          the name of the file to which the certificate shall be saved
	 * @param serialNumber
	 *          the serial number of the certificate to be created
	 * @param extensions
	 *          an array of X509v3 extensions to be added to the certificate
	 * 
	 * @return the certificate just created
	 */
	public X509Certificate createCertificate(Name subject,
	                                         PublicKey pk,
	                                         Name issuer,
	                                         PrivateKey sk,
	                                         AlgorithmID algorithm,
	                                         String fileName,
	                                         int serialNumber,
	                                         V3Extension[] extensions)
	    throws Exception
	{

		final X509Certificate cert = new X509Certificate();

		cert.setSerialNumber(BigInteger.valueOf(serialNumber));
		cert.setSubjectDN(subject);
		cert.setPublicKey(pk);
		cert.setIssuerDN(issuer);

		final GregorianCalendar date = new GregorianCalendar();
		// not before now
		cert.setValidNotBefore(date.getTime());

		date.add(Calendar.YEAR, 1);
		cert.setValidNotAfter(date.getTime());

		if (extensions != null) {
			for (int i = 0; i < extensions.length; i++) {
				cert.addExtension(extensions[i]);
			}
		}

		// sign certificate
		cert.sign(algorithm, sk);

		OutputStream os = null;

		if (fileName != null) {
			try {
				os = new FileOutputStream(fileName);
				cert.writeTo(os);
			} finally {
				if (os != null) {
					try {
						os.close();
					} catch (final IOException e) {
						// ignore
					}
				}
			}
		}
		return cert;
	}

	/**
	 * Creates a new self-signed X509v3 certificate with a lot of extensions.
	 * <p>
	 * To avoid the time consuming process of key creation, the issuer certificate
	 * and private key are created from a PEM encoded file "caRSA.pem" located in
	 * a "test" directory. Run the <code>CreateCertificates</code> demo for
	 * creating the required structures and saving them to the file requested
	 * above, if it does not yet exist.
	 */
	public void start() {
		start(null);
	}

	/**
	 * Creates a new self-signed X509v3 certificate with a lot of extensions.
	 * <p>
	 * To avoid the time consuming process of key creation, the issuer certificate
	 * and private key are created from a PEM encoded file "caRSA.pem" located in
	 * a "test" directory. Run the <code>CreateCertificates</code> demo for
	 * creating the required structures and saving them to the file requested
	 * above, if it does not yet exist.
	 * 
	 * @param fileName
	 *          the name to which to write the cert
	 */
	public void start(String fileName) {

		try {
			final Vector extensions = new Vector();
			final RSAPrivateKey privateKey = (RSAPrivateKey) IaikKeyStore.getPrivateKey(
			    IaikKeyStore.RSA, IaikKeyStore.SZ_1024);

			final ObjectID iaikDemoPolicy1 = new ObjectID("1.3.6.1.4.1.2706.2.2.1.1.1.1.1",
			    "IAIK Demo CA 1");
			final ObjectID iaikDemoPolicy2 = new ObjectID("1.3.6.1.4.1.2706.2.2.1.2.1.1.1",
			    "IAIK Demo CA 2");

			final Name subject = new Name();
			subject.addRDN(ObjectID.country, "AT");
			subject.addRDN(ObjectID.locality, "Graz");
			subject.addRDN(ObjectID.organization, "UT Graz");
			subject.addRDN(ObjectID.organizationalUnit, "IAIK");
			subject.addRDN(ObjectID.commonName, "Joe Testuser");

			// AuthorityKeyIdentifier
			final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
			authorityKeyIdentifier.setKeyIdentifier(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });
			final GeneralName generalName = new GeneralName(
			    GeneralName.uniformResourceIdentifier, "http://ca.test.com/");
			authorityKeyIdentifier.setAuthorityCertIssuer(new GeneralNames(generalName));
			authorityKeyIdentifier.setAuthorityCertSerialNumber(new BigInteger(
			    "235123512365215"));
			extensions.addElement(authorityKeyIdentifier);

			// BasicConstraints
			final BasicConstraints basicConstraints = new BasicConstraints(true, 1);
			basicConstraints.setCritical(true);
			extensions.addElement(basicConstraints);

			// CertificatePolicies
			final PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(null, null,
			    "This certificate may be used for demonstration purposes only!");
			final PolicyInformation policyInformation = new PolicyInformation(iaikDemoPolicy1,
			    new PolicyQualifierInfo[] { policyQualifierInfo });
			final CertificatePolicies certificatePolicies = new CertificatePolicies(
			    new PolicyInformation[] { policyInformation });
			extensions.addElement(certificatePolicies);

			// CRL distribution point
			final String crlUri = "http://ca.iaik.at/test.crl";
			final DistributionPoint distributionPoint = new DistributionPoint(
			    new String[] { crlUri });
			distributionPoint.setReasonFlags(DistributionPoint.keyCompromise);
			final CRLDistributionPoints cRLDistributionPoints = new CRLDistributionPoints(
			    distributionPoint);

			extensions.addElement(cRLDistributionPoints);

			GeneralNames generalNames = new GeneralNames();
			generalNames.addName(new GeneralName(GeneralName.uniformResourceIdentifier,
			    "http://www.test.com/"));

			// IssuerAltName
			final IssuerAltName issuerAltName = new IssuerAltName(generalNames);
			extensions.addElement(issuerAltName);

			// KeyUsage
			final KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature
			    | KeyUsage.nonRepudiation | KeyUsage.keyCertSign | KeyUsage.cRLSign);

			extensions.addElement(keyUsage);

			// NameConstraints
			final NameConstraints nameConstraints = new NameConstraints();
			final GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(
			    GeneralName.rfc822Name, "*.tu-graz.ac.at"));
			generalSubtree.setMinimum(1);
			generalSubtree.setMaximum(3);
			nameConstraints.setPermittedSubtrees(new GeneralSubtree[] { generalSubtree });
			extensions.addElement(nameConstraints);

			// PolicyConstraints
			final PolicyConstraints policyConstraints = new PolicyConstraints();
			policyConstraints.setRequireExplicitPolicy(3);
			policyConstraints.setInhibitPolicyMapping(7);
			extensions.addElement(policyConstraints);

			// PolicyMappings
			final PolicyMappings policyMappings = new PolicyMappings();
			policyMappings.addMapping(new PolicyMapping(iaikDemoPolicy1, iaikDemoPolicy2));
			extensions.addElement(policyMappings);

			// PrivateKeyUsagePeriod
			final GregorianCalendar gc = new GregorianCalendar();
			gc.add(Calendar.YEAR, 1);
			final PrivateKeyUsagePeriod privateKeyUsagePeriod = new PrivateKeyUsagePeriod(
			    new Date(), gc.getTime());
			extensions.addElement(privateKeyUsagePeriod);

			// SubjectAltName
			generalNames = new GeneralNames();
			generalNames.addName(new GeneralName(GeneralName.iPAddress, "127.0.0.1"));
			final SubjectAltName subjectAltName = new SubjectAltName(generalNames);
			extensions.addElement(subjectAltName);

			// SubjectKeyIdentifier
			final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(
			    new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });
			extensions.addElement(subjectKeyIdentifier);

			// AuthorityInfoAccess
			final ObjectID accessMethod = ObjectID.ocsp;
			final GeneralName accessLocation = new GeneralName(
			    GeneralName.uniformResourceIdentifier, "http://test.ca.com/ocsp");

			final AccessDescription accessDescription = new AccessDescription(accessMethod,
			    accessLocation);
			final AuthorityInfoAccess authorityInfoAccess = new AuthorityInfoAccess(
			    accessDescription);
			extensions.addElement(authorityInfoAccess);

			final V3Extension[] e = new V3Extension[extensions.size()];
			extensions.copyInto(e);

			final X509Certificate cert = createCertificate(subject, privateKey.getPublicKey(),
			    subject, privateKey, AlgorithmID.sha1WithRSAEncryption, null, 1234, e);

			final byte[] test = cert.toByteArray();
			// send certificate to ...
			if (fileName != null) {
				iaik.utils.Util.saveToFile(test, fileName);
			}

			// receive certificte
			final X509Certificate new_cert = new X509Certificate(test);
			System.out.println(new_cert.toString(true));

		} catch (final Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the X509v3 extensions test procedure.
	 */
	public static void main(String[] argv) {

		DemoUtil.initDemos();
		(new CertificateExtensions()).start((argv.length == 0) ? null : argv[0]);
	}
}
