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
import iaik.asn1.SEQUENCE;
import iaik.asn1.UTF8String;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.Name;
import iaik.asn1.structures.PolicyInformation;
import iaik.asn1.structures.PolicyQualifierInfo;
import iaik.security.provider.IAIK;
import iaik.security.rsa.RSAPrivateKey;
import iaik.x509.V3Extension;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.CertificatePolicies;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectDirectoryAttributes;
import iaik.x509.extensions.qualified.BiometricInfo;
import iaik.x509.extensions.qualified.QCStatements;
import iaik.x509.extensions.qualified.structures.BiometricData;
import iaik.x509.extensions.qualified.structures.QCStatement;
import iaik.x509.extensions.qualified.structures.QCSyntaxV2;
import iaik.x509.extensions.qualified.structures.etsi.QcEuCompliance;
import iaik.x509.extensions.qualified.structures.etsi.QcEuLimitValue;
import iaik.x509.extensions.qualified.structures.etsi.QcEuPDS;
import iaik.x509.extensions.qualified.structures.etsi.QcEuRetentionPeriod;
import iaik.x509.extensions.qualified.structures.etsi.QcEuSSCD;
import iaik.x509.extensions.qualified.structures.etsi.QcEuPDS.PdsLocation;
import iaik.x509.qualified.QualifiedCertificate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import java.util.Collection;
import java.util.GregorianCalendar;
import java.util.Vector;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;

/**
 * This class tests the QualifiedCertificate implementation.
 * <p>
 * A QCStatement is used by indicating that the certificate created in this test
 * is a qualified certificate. The QCStatement is a pricate one implemented by
 * class {@link demo.x509.qualified.MyPrivateQCStatement MyPrivateQCStatement}.
 * The corresponding statement ID is registered as indicating a qualyfied
 * certificate. Beside the private statement two further QCStatement objects are
 * added to the certificate, a QCSyntaxV2 and a second "private" statement only
 * containing a statement ID and no statement info. The biometric data hash
 * calculated for the BiometricInfo extension is calculated "on the fly" by
 * connecting to the given source data uri. Note that this may not be work when
 * you run the demo because for some reason you may not be able to connect to
 * the URL used. Please change the corresponding code sequence by using a
 * different URL (or, for instance, supplying the data from an input stream).
 * <p>
 * To avoid the time consuming process of key creation, the issuer certificate
 * and private key are read in from a keystore "jce.keystore" located in the
 * current working directory (if it yet not does exist, please run
 * {@link demo.keystore.SetupKeyStore SetupKeyStore} for creating it.
 * 
 * @version File Revision <!-- $$Revision: --> 21 <!-- $ -->
 */
public class QualifiedCert implements IAIKDemo {

	/**
	 * Creates a certificate.
	 * <p>
	 * 
	 * @param subject
	 *          the certificate subject
	 * @param pk
	 *          the subject's public key to be certified
	 * @param issuer
	 *          the name of the certification authority that issues the
	 *          certificate
	 * @param sk
	 *          the issuer's private key for signing the certificate
	 * @param algorithm
	 *          the ID of the signature algorithm
	 * @param serialNumber
	 *          the serial number of the certifcate to be created
	 * @param extensions
	 *          an array of X509v3 extensions to be added to the certificate
	 * 
	 * @return the certificate just created
	 */
	public QualifiedCertificate createCertificate(Name subject,
	                                              PublicKey pk,
	                                              Name issuer,
	                                              PrivateKey sk,
	                                              AlgorithmID algorithm,
	                                              int serialNumber,
	                                              V3Extension[] extensions)
	    throws Exception
	{

		QualifiedCertificate cert = new QualifiedCertificate();

		// basic fields
		cert.setSerialNumber(BigInteger.valueOf(serialNumber));
		cert.setSubjectDN(subject);
		cert.setPublicKey(pk);
		cert.setIssuerDN(issuer);

		GregorianCalendar date = new GregorianCalendar();
		// not before now
		cert.setValidNotBefore(date.getTime());

		date.add(Calendar.YEAR, 1);
		cert.setValidNotAfter(date.getTime());

		if (extensions != null) for (int i = 0; i < extensions.length; i++)
			cert.addExtension(extensions[i]);

		cert.sign(algorithm, sk);

		return cert;
	}

	/**
	 * Starts the test.
	 */
	public void start() {

		try {
			Vector extensions = new Vector();
			// read issuer cert/key and user private key from keystore
			X509Certificate caCert = IaikKeyStore.getCaCertificate(IaikKeyStore.RSA);
			RSAPrivateKey caPrivateKey = (RSAPrivateKey) IaikKeyStore
			    .getCaPrivateKey(IaikKeyStore.RSA);
			RSAPrivateKey privateKey = (RSAPrivateKey) IaikKeyStore.getPrivateKey(
			    IaikKeyStore.RSA, IaikKeyStore.SZ_1024);

			Name subject = new Name();
			subject.addRDN(ObjectID.country, "AT");
			subject.addRDN(ObjectID.locality, "Graz");
			subject.addRDN(ObjectID.organization, "TU Graz");
			subject.addRDN(ObjectID.organizationalUnit, "IAIK");
			subject.addRDN(ObjectID.commonName, "Joe Testuser");

			// SubjectDirectoryAttributes
			Attribute[] attributes = new Attribute[2];
			// Gender:
			PrintableString gender = new PrintableString("M");
			attributes[0] = new Attribute(ObjectID.gender, new ASN1Object[] { gender });
			// Postal Address:
			SEQUENCE postalAddress = new SEQUENCE();
			postalAddress.addComponent(new UTF8String("A-8010 Graz, Austria"));
			postalAddress.addComponent(new UTF8String("Inffeldgasse 16A"));
			attributes[1] = new Attribute(ObjectID.postalAddress,
			    new ASN1Object[] { postalAddress });
			// create a SubjectDirectoryAttributes extension object:
			SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes();
			// set the attributes:
			sda.setAttributes(attributes);
			extensions.addElement(sda);

			// Certificate Policies
			ObjectID iaikTest = new ObjectID("1.3.6.1.4.1.2706.2.2.1.3.1.1.1");
			PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(null, null,
			    "Qualified cert, only to be used for demonstration purposes!");
			PolicyInformation policyInformation = new PolicyInformation(iaikTest,
			    new PolicyQualifierInfo[] { policyQualifierInfo });
			CertificatePolicies certificatePolicies = new CertificatePolicies(
			    new PolicyInformation[] { policyInformation });
			extensions.addElement(certificatePolicies);
			// uncomment the follwing line if you want to indicate the qualified cert
			// via Certificate Policy (we use a QCStatement here; see below)
			// QualifiedCertificate.registerQualifiedPolicyIDs(new ObjectID [] {
			// iaikTest });

			// KeyUsage
			KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
			extensions.addElement(keyUsage);

			// BiometricInfo
			BiometricData biometricData = new BiometricData(BiometricData.picture);
			/*
			 * We get and calculate the biometric hash from a stream. You also may let
			 * class BiometricData connect to and calculate the hash from a source
			 * data uri by calling:
			 * biometricData.setBiometricDataHash(AlgorithmID.sha, sourceDataUri);
			 */
			String sourceDataUri = "http://iaik.test.at/people/pics/johndoe.jpg";
			biometricData.setSourceDataUri(sourceDataUri);
			biometricData.setBiometricDataHash(AlgorithmID.sha, new ByteArrayInputStream(
			    jdoegif));

			BiometricInfo biometricInfo = new BiometricInfo(
			    new BiometricData[] { biometricData });
			extensions.addElement(biometricInfo);

			// QCStatements
			// register a private statement implementation
			QCStatement.register(MyPrivateQCStatement.statementID, MyPrivateQCStatement.class);

			// register QCEuCompliance as indicating a qualified certificate
			QualifiedCertificate
			    .registerQualifiedQCStatementIDs(new ObjectID[] { QcEuCompliance.statementID });
			MyPrivateQCStatement myPrivateStatement = new MyPrivateQCStatement(
			    "This is a qualified cert!");

			// QCSyntaxV2
			ObjectID semID = new ObjectID("1.3.6.1.4.1.2706.2.2.1.3");
			GeneralName[] genNames = new GeneralName[1];
			genNames[0] = new GeneralName(GeneralName.uniformResourceIdentifier,
			    "http//ca.iaik.at/registrationAuthority");
			QCSyntaxV2 qcSyntaxV2 = new QCSyntaxV2(semID, genNames);

			// QCEuCompliance
			QcEuCompliance qcCompliance = new QcEuCompliance();
			
			// QcEuRetentionPeriod
			int retentionPeriod = 10;
			QcEuRetentionPeriod qcRetentionPeriod = new QcEuRetentionPeriod(retentionPeriod);
			
			// QcEuLimitValue
			String currency = "EUR";
			int amount = 1;
			int exponent = 4;
			QcEuLimitValue qcLimitValue = new QcEuLimitValue(currency, amount, exponent);
			
			// QcEuSSCD
			QcEuSSCD qcSSCD = new QcEuSSCD();
			
			// QcEuPDS
			QcEuPDS qcEuPDS = new QcEuPDS();
			qcEuPDS.addPdsLocation(new PdsLocation("https://testca.iaik.at/pds/de/pds.pdf", "de"));
	    qcEuPDS.addPdsLocation(new PdsLocation("https://testca.iaik.at/pds/en/pds.pdf", "en"));

			QCStatement[] qcStatements = new QCStatement[8];
			qcStatements[0] = new QCStatement(qcSyntaxV2);
			qcStatements[1] = new QCStatement(myPrivateStatement);
			// we add a QCStatement consisting only of a statementId and no
			// statementInfo
			ObjectID newStatementID = new ObjectID("1.3.6.1.4.1.2706.2.2.1.5", "NewQCStatement");
			qcStatements[2] = new QCStatement(newStatementID);
			qcStatements[3] = new QCStatement(qcCompliance);
			qcStatements[4] = new QCStatement(qcRetentionPeriod);
			qcStatements[5] = new QCStatement(qcLimitValue);
			qcStatements[6] = new QCStatement(qcSSCD);
			qcStatements[7] = new QCStatement(qcEuPDS);

			QCStatements qcStatementsExt = new QCStatements(qcStatements);
			extensions.addElement(qcStatementsExt);

			V3Extension[] e = new V3Extension[extensions.size()];
			extensions.copyInto(e);

			// create the cert
			QualifiedCertificate cert = createCertificate(subject, privateKey.getPublicKey(),
			    (Name) caCert.getIssuerDN(), caPrivateKey, AlgorithmID.sha1WithRSAEncryption,
			    1234, e);

			// encode the user and issuer cert to a stream
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			baos.write(cert.toByteArray());
			baos.write(caCert.toByteArray());
			byte[] test = baos.toByteArray();

			// receive certificte chain
			ByteArrayInputStream bais = new ByteArrayInputStream(test);
			CertificateFactory cf = CertificateFactory.getInstance("Qualified", "IAIK");
			Collection c = cf.generateCertificates(bais);
			Object[] certObjs = c.toArray();
			X509Certificate[] certs = new X509Certificate[certObjs.length];
			for (int i = 0; i < certs.length; i++) {
				certs[i] = (X509Certificate) certObjs[i];
			}
			// we want (qualified) end user cert at index 0
			certs = iaik.utils.Util.arrangeCertificateChain(certs, false);

			X509Certificate cacert = certs[1];
			System.out.println("Issuer: " + cacert.getSubjectDN());
			QualifiedCertificate userCert = (QualifiedCertificate) certs[0];
			userCert.verify(cacert.getPublicKey());
			System.out.println("Received qualified Cert:");
			System.out.println(userCert.toString(true));
			System.out.println("This cert contains the following qc statements:");
			qcStatements = userCert.getQCStatements().getQCStatements();
			System.out.println("This cert contains the following statements:");
			for (int i = 0; i < qcStatements.length; i++) {
				System.out.println(qcStatements[i]);
			}
			QCStatement[] qualifiedStatements = userCert.getQualifiedQCStatements();
			System.out.println("This cert contains the following qualified statements:");
			for (int i = 0; i < qualifiedStatements.length; i++) {
				System.out.println(qualifiedStatements[i]);
			}

			// we try to get the source data from the inherent uri to verify the
			// biometric hash
			System.out.println("Try to verify biometric data hash...");
			BiometricInfo bioInfo = userCert.getBiometricInfo();
			// we know that only one BiometricData is included
			BiometricData bioData = bioInfo.getBiometricDatas()[0];
			System.out.println(bioData);
			/*
			 * Verify the BiometricData by explicitly supplying the data. If no data
			 * is supplied by calling verifyBiometricDataHash() only, it is tried to
			 * connect and get the data from the source data uri
			 */
			boolean hashOK = bioData.verifyBiometricDataHash(new ByteArrayInputStream(jdoegif));
			System.out.println("BiometricDataHash " + (hashOK ? "OK" : "wrong"));

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Tests the QualifiedCertificate implementation.
	 */
	public static void main(String[] argv)
	    throws Exception
	{
		Security.insertProviderAt(new IAIK(), 2);
		(new QualifiedCert()).start();
		iaik.utils.Util.waitKey();
	}

	// the image from which the BiometricData hash is calculated
	private static byte[] jdoegif = { (byte) 0x47, (byte) 0x49, (byte) 0x46, (byte) 0x38,
	    (byte) 0x39, (byte) 0x61, (byte) 0x2F, (byte) 0x00, (byte) 0x46, (byte) 0x00,
	    (byte) 0xA2, (byte) 0x07, (byte) 0x00, (byte) 0xD4, (byte) 0xD4, (byte) 0xD4,
	    (byte) 0x8E, (byte) 0x8E, (byte) 0x8E, (byte) 0xF4, (byte) 0xF4, (byte) 0xF4,
	    (byte) 0xAC, (byte) 0xAC, (byte) 0xAC, (byte) 0x3F, (byte) 0x3F, (byte) 0x3F,
	    (byte) 0x68, (byte) 0x68, (byte) 0x68, (byte) 0x00, (byte) 0x00, (byte) 0x00,
	    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x21, (byte) 0xF9, (byte) 0x04,
	    (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x07, (byte) 0x00, (byte) 0x2C,
	    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x2F, (byte) 0x00,
	    (byte) 0x46, (byte) 0x00, (byte) 0x40, (byte) 0x03, (byte) 0xFF, (byte) 0x78,
	    (byte) 0xBA, (byte) 0xDC, (byte) 0xFE, (byte) 0x30, (byte) 0xCA, (byte) 0x27,
	    (byte) 0xC0, (byte) 0x20, (byte) 0x44, (byte) 0xB4, (byte) 0x32, (byte) 0xA6,
	    (byte) 0xFF, (byte) 0x82, (byte) 0x76, (byte) 0x04, (byte) 0x46, (byte) 0x69,
	    (byte) 0x96, (byte) 0x9D, (byte) 0x42, (byte) 0x16, (byte) 0x9F, (byte) 0x03,
	    (byte) 0x00, (byte) 0x90, (byte) 0x40, (byte) 0x9C, (byte) 0x25, (byte) 0x11,
	    (byte) 0x34, (byte) 0x02, (byte) 0x99, (byte) 0xB5, (byte) 0x0A, (byte) 0x50,
	    (byte) 0x88, (byte) 0x07, (byte) 0x19, (byte) 0xED, (byte) 0xB4, (byte) 0x03,
	    (byte) 0x90, (byte) 0x4C, (byte) 0x85, (byte) 0x00, (byte) 0x8C, (byte) 0xB7,
	    (byte) 0x28, (byte) 0x18, (byte) 0x52, (byte) 0x8C, (byte) 0x23, (byte) 0x0D,
	    (byte) 0xCA, (byte) 0x6C, (byte) 0x09, (byte) 0x87, (byte) 0x25, (byte) 0x56,
	    (byte) 0xB5, (byte) 0x45, (byte) 0x5A, (byte) 0x7E, (byte) 0x00, (byte) 0x86,
	    (byte) 0xDD, (byte) 0xD6, (byte) 0x11, (byte) 0x0A, (byte) 0x1D, (byte) 0x92,
	    (byte) 0x8D, (byte) 0x80, (byte) 0x78, (byte) 0xCC, (byte) 0x76, (byte) 0x19,
	    (byte) 0x6E, (byte) 0x6D, (byte) 0x8A, (byte) 0x31, (byte) 0x30, (byte) 0x00,
	    (byte) 0x92, (byte) 0x5F, (byte) 0xF1, (byte) 0xAA, (byte) 0x13, (byte) 0x5B,
	    (byte) 0x70, (byte) 0xC2, (byte) 0xD9, (byte) 0x68, (byte) 0x7E, (byte) 0x0E,
	    (byte) 0x03, (byte) 0x7D, (byte) 0x54, (byte) 0x84, (byte) 0x76, (byte) 0x0C,
	    (byte) 0x18, (byte) 0x3C, (byte) 0x00, (byte) 0x6B, (byte) 0x0B, (byte) 0x03,
	    (byte) 0x58, (byte) 0x54, (byte) 0x79, (byte) 0x32, (byte) 0x88, (byte) 0x0A,
	    (byte) 0x7B, (byte) 0x34, (byte) 0x7F, (byte) 0x79, (byte) 0x0E, (byte) 0x47,
	    (byte) 0x98, (byte) 0x0C, (byte) 0x3E, (byte) 0x26, (byte) 0x5E, (byte) 0x99,
	    (byte) 0x0B, (byte) 0x60, (byte) 0x3F, (byte) 0x11, (byte) 0x39, (byte) 0x6F,
	    (byte) 0x94, (byte) 0xA1, (byte) 0xA9, (byte) 0xAA, (byte) 0x38, (byte) 0x36,
	    (byte) 0xAB, (byte) 0x38, (byte) 0x05, (byte) 0x04, (byte) 0x75, (byte) 0x64,
	    (byte) 0x4F, (byte) 0xAE, (byte) 0x12, (byte) 0x4A, (byte) 0xB5, (byte) 0x38,
	    (byte) 0x01, (byte) 0x74, (byte) 0x01, (byte) 0x4E, (byte) 0x91, (byte) 0x96,
	    (byte) 0x35, (byte) 0x40, (byte) 0x4E, (byte) 0xA8, (byte) 0x79, (byte) 0x60,
	    (byte) 0x58, (byte) 0x4F, (byte) 0x46, (byte) 0x36, (byte) 0xA0, (byte) 0xA9,
	    (byte) 0x02, (byte) 0xC6, (byte) 0x3B, (byte) 0xA6, (byte) 0x05, (byte) 0xCA,
	    (byte) 0x2D, (byte) 0x8F, (byte) 0x06, (byte) 0x5A, (byte) 0x2E, (byte) 0x33,
	    (byte) 0x25, (byte) 0x37, (byte) 0x60, (byte) 0xD1, (byte) 0x02, (byte) 0x82,
	    (byte) 0x5C, (byte) 0x5A, (byte) 0x57, (byte) 0x49, (byte) 0x52, (byte) 0x9F,
	    (byte) 0x72, (byte) 0x6A, (byte) 0x26, (byte) 0x9C, (byte) 0xA5, (byte) 0xD0,
	    (byte) 0x0F, (byte) 0xBF, (byte) 0x9F, (byte) 0xD3, (byte) 0xB7, (byte) 0x99,
	    (byte) 0xA3, (byte) 0x76, (byte) 0xD3, (byte) 0x53, (byte) 0xAA, (byte) 0x60,
	    (byte) 0xE7, (byte) 0x41, (byte) 0x58, (byte) 0x8D, (byte) 0xB8, (byte) 0xA6,
	    (byte) 0x43, (byte) 0x91, (byte) 0xAE, (byte) 0x52, (byte) 0x04, (byte) 0x5E,
	    (byte) 0x7E, (byte) 0x55, (byte) 0xA3, (byte) 0x57, (byte) 0x62, (byte) 0x18,
	    (byte) 0x03, (byte) 0x66, (byte) 0x61, (byte) 0x0C, (byte) 0x6E, (byte) 0xE9,
	    (byte) 0x22, (byte) 0x8D, (byte) 0x9A, (byte) 0xC2, (byte) 0x31, (byte) 0xB0,
	    (byte) 0x28, (byte) 0x31, (byte) 0x22, (byte) 0x15, (byte) 0xEA, (byte) 0x9A,
	    (byte) 0x09, (byte) 0x02, (byte) 0x7D, (byte) 0x02, (byte) 0xA0, (byte) 0x22,
	    (byte) 0x44, (byte) 0x23, (byte) 0xE0, (byte) 0x1A, (byte) 0xAE, (byte) 0x8F,
	    (byte) 0x5B, (byte) 0x46, (byte) 0x81, (byte) 0x9C, (byte) 0xC0, (byte) 0xAC,
	    (byte) 0x9F, (byte) 0x2A, (byte) 0x6E, (byte) 0x35, (byte) 0x94, (byte) 0xC9,
	    (byte) 0xB0, (byte) 0x87, (byte) 0x4B, (byte) 0x57, (byte) 0x83, (byte) 0x01,
	    (byte) 0x1E, (byte) 0x3F, (byte) 0x96, (byte) 0x19, (byte) 0x29, (byte) 0x0F,
	    (byte) 0x05, (byte) 0x99, (byte) 0x0B, (byte) 0x59, (byte) 0x40, (byte) 0xB9,
	    (byte) 0x4C, (byte) 0x75, (byte) 0x01, (byte) 0x48, (byte) 0xCD, (byte) 0x71,
	    (byte) 0x2A, (byte) 0x68, (byte) 0xB9, (byte) 0x42, (byte) 0x88, (byte) 0x05,
	    (byte) 0x0E, (byte) 0x23, (byte) 0x80, (byte) 0xB5, (byte) 0xC4, (byte) 0xD1,
	    (byte) 0x70, (byte) 0x42, (byte) 0xB1, (byte) 0xD6, (byte) 0x95, (byte) 0x21,
	    (byte) 0x00, (byte) 0x84, (byte) 0xB0, (byte) 0xCC, (byte) 0x44, (byte) 0x74,
	    (byte) 0x9E, (byte) 0xA8, (byte) 0x19, (byte) 0x4D, (byte) 0xAD, (byte) 0x24,
	    (byte) 0x84, (byte) 0xB0, (byte) 0x6E, (byte) 0x00, (byte) 0x2F, (byte) 0x32,
	    (byte) 0x3A, (byte) 0x1E, (byte) 0x46, (byte) 0xC1, (byte) 0x28, (byte) 0xF4,
	    (byte) 0xC1, (byte) 0x0B, (byte) 0x11, (byte) 0x32, (byte) 0xF2, (byte) 0x05,
	    (byte) 0xE9, (byte) 0xD5, (byte) 0xA2, (byte) 0x4F, (byte) 0x10, (byte) 0xAC,
	    (byte) 0x40, (byte) 0xC4, (byte) 0x65, (byte) 0xA5, (byte) 0x80, (byte) 0x53,
	    (byte) 0x5A, (byte) 0x35, (byte) 0x46, (byte) 0xC6, (byte) 0xB2, (byte) 0x74,
	    (byte) 0x2A, (byte) 0x77, (byte) 0xD1, (byte) 0x1D, (byte) 0x88, (byte) 0x46,
	    (byte) 0x02, (byte) 0xBC, (byte) 0x1A, (byte) 0x8B, (byte) 0x6A, (byte) 0x31,
	    (byte) 0x5D, (byte) 0x1B, (byte) 0x3A, (byte) 0x0F, (byte) 0x94, (byte) 0xA2,
	    (byte) 0xB0, (byte) 0x20, (byte) 0x96, (byte) 0x47, (byte) 0xC4, (byte) 0x97,
	    (byte) 0x90, (byte) 0x86, (byte) 0xFA, (byte) 0xB1, (byte) 0xA3, (byte) 0xB8,
	    (byte) 0x2C, (byte) 0x55, (byte) 0x12, (byte) 0xF6, (byte) 0xD6, (byte) 0x95,
	    (byte) 0x88, (byte) 0x39, (byte) 0x46, (byte) 0xDB, (byte) 0x83, (byte) 0x9F,
	    (byte) 0x7A, (byte) 0x57, (byte) 0xA1, (byte) 0xAA, (byte) 0x7A, (byte) 0xB1,
	    (byte) 0x71, (byte) 0x1C, (byte) 0x94, (byte) 0x43, (byte) 0x08, (byte) 0x8C,
	    (byte) 0x5C, (byte) 0x4B, (byte) 0x84, (byte) 0xD7, (byte) 0x89, (byte) 0xB9,
	    (byte) 0xCB, (byte) 0xCC, (byte) 0xD9, (byte) 0x41, (byte) 0x6D, (byte) 0x53,
	    (byte) 0xF4, (byte) 0x8C, (byte) 0xA9, (byte) 0x3D, (byte) 0x66, (byte) 0xA8,
	    (byte) 0x3D, (byte) 0x7C, (byte) 0xEA, (byte) 0xCB, (byte) 0x0C, (byte) 0x93,
	    (byte) 0x9D, (byte) 0x2D, (byte) 0x7B, (byte) 0x98, (byte) 0x61, (byte) 0xFA,
	    (byte) 0x03, (byte) 0x06, (byte) 0xB1, (byte) 0x61, (byte) 0x5D, (byte) 0x3D,
	    (byte) 0x02, (byte) 0x7E, (byte) 0xB4, (byte) 0x78, (byte) 0x48, (byte) 0xE1,
	    (byte) 0x2B, (byte) 0x95, (byte) 0xF3, (byte) 0xBA, (byte) 0x86, (byte) 0x41,
	    (byte) 0xB8, (byte) 0x27, (byte) 0x8C, (byte) 0xBA, (byte) 0x60, (byte) 0x3A,
	    (byte) 0xDF, (byte) 0xA0, (byte) 0x5B, (byte) 0xFB, (byte) 0x97, (byte) 0xE9,
	    (byte) 0x1A, (byte) 0x57, (byte) 0xAB, (byte) 0x4A, (byte) 0x00, (byte) 0x00,
	    (byte) 0x3B };

}
