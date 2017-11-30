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

package demo.x509.attr;

import iaik.asn1.ASN;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.attr.Holder;
import iaik.x509.attr.IssuerSerial;
import iaik.x509.attr.SecurityCategory;
import iaik.x509.attr.Target;
import iaik.x509.attr.TargetException;
import iaik.x509.attr.TargetGroup;
import iaik.x509.attr.TargetName;
import iaik.x509.attr.Targets;
import iaik.x509.attr.V2Form;
import iaik.x509.attr.attributes.AccessIdentity;
import iaik.x509.attr.attributes.ChargingIdentity;
import iaik.x509.attr.attributes.Clearance;
import iaik.x509.attr.attributes.Group;
import iaik.x509.attr.attributes.Role;
import iaik.x509.attr.attributes.ServiceAuthenticationInfo;
import iaik.x509.attr.extensions.AuditIdentity;
import iaik.x509.attr.extensions.NoRevAvail;
import iaik.x509.attr.extensions.ProxyInfo;
import iaik.x509.attr.extensions.TargetInformation;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Random;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;
import demo.util.DemoUtil;

/**
 * This class demonstrates the usage of the IAIK-JCE
 * {@link iaik.x509.attr.AttributeCertificate AttributeCertificate} extensions.
 * The demo creates a attribute certificate, adds some attributes and
 * extensions, signs and encodes the certificate, decodes and parses it and
 * validates the signature and the included attributes and extensions.
 * Optionally the attribute certificate may be saved to a file.
 * <p>
 * To avoid the time consuming process of key creation, the issuer certificate
 * and private key are read in from a keystore "jce.keystore" located in the
 * current working directory (if it does not yet exist, please run
 * {@link demo.keystore.SetupKeyStore SetupKeyStore} for creating it.
 * 
 * @version File Revision <!-- $$Revision: --> 15 <!-- $ -->
 */
public class AttributeCertificateDemo implements IAIKDemo {

	/**
	 * Public key certificate of the AC issuer.
	 */
	X509Certificate[] acIssuerCerts_;
	/**
	 * Private key of the AC issuer.
	 */
	PrivateKey acIssuerPrivateKey_;
	/**
	 * Public key of the AC issuer.
	 */
	PublicKey acIssuerPublicKey_;
	/**
	 * Base certificate.
	 */
	X509Certificate[] pkcCerts_;
	/**
	 * Role specification certificate.
	 */
	AttributeCertificate roleSpecificationCert_;
	/**
	 * Role name.
	 */
	GeneralName roleName_;
	/**
	 * Random.
	 */
	Random random_;

	/**
	 * Default constructor. Reads issuer cert and key, and base cert from demo
	 * keystore "jce.keystore".
	 */
	public AttributeCertificateDemo() {
		// read AC issuer information from demo keystore
		acIssuerCerts_ = IaikKeyStore.getACIssuerCertificateChain();
		acIssuerPrivateKey_ = IaikKeyStore.getACIssuerPrivateKey();
		acIssuerPublicKey_ = acIssuerCerts_[0].getPublicKey();
		// read the public key certificate to which to be linked from the attribute
		// certificate
		pkcCerts_ = IaikKeyStore.getCertificateChain(IaikKeyStore.RSA, IaikKeyStore.SZ_1024);
		// create a Role name
		roleName_ = new GeneralName(GeneralName.uniformResourceIdentifier, "urn:sysadmin");

		random_ = new Random();
	}

	/**
	 * Runs the demo without saving the attribute certificate to a file.
	 */
	public void start() {
		start(null);
	}

	/**
	 * Starts the demo.
	 * 
	 * @param fileName
	 *          the name of the file to which to write the cert, if no fileName is
	 *          specified, the attribute certificate is not written to a file
	 */
	public void start(String fileName) {

		try {

			// only for this sample we create a rudimentary role specification
			// certificate where nothing else is set as holder and issuer fiels
			roleSpecificationCert_ = new AttributeCertificate();
			Name roleIssuer = new Name();
			roleIssuer.addRDN(ObjectID.commonName, "Demo Role Specification Cert");
			roleSpecificationCert_.setIssuer(new V2Form(roleIssuer));
			Holder roleHolder = new Holder();
			roleHolder.setEntityName(new GeneralNames(roleName_));
			roleSpecificationCert_.setHolder(roleHolder);
			// in practice we now would add validity, extensions,... and sign the
			// cert...

			// create Attribute Certificate
			AttributeCertificate attributeCertificate = new AttributeCertificate();
			// issuer
			Name issuerName = (Name) acIssuerCerts_[0].getSubjectDN();
			V2Form v2Form = new V2Form(issuerName);
			attributeCertificate.setIssuer(v2Form);
			// holder (from base certificate)
			X509Certificate baseCert = pkcCerts_[0];
			Holder holder = new Holder();
			holder.setBaseCertificateID(baseCert);
			attributeCertificate.setHolder(holder);
			// for this demo we use a ramdomly generated serial number
			attributeCertificate.setSerialNumber(new BigInteger(20, random_));
			// validity
			GregorianCalendar c = new GregorianCalendar();
			Date notBeforeTime = c.getTime();
			c.add(Calendar.MONTH, 1);
			Date notAfterTime = c.getTime();
			attributeCertificate.setNotBeforeTime(notBeforeTime);
			attributeCertificate.setNotAfterTime(notAfterTime);
			// add attributes
			addAttributes(attributeCertificate);
			// add extensions
			addExtensions(attributeCertificate);
			// sign certificate
			attributeCertificate.sign(AlgorithmID.sha1WithRSAEncryption, acIssuerPrivateKey_);

			byte[] test = attributeCertificate.getEncoded();
			// send certificate to ...
			if (fileName != null) {
				iaik.utils.Util.saveToFile(test, fileName);
				System.out.println("Saved certificate to " + fileName);
			}

			// receive certificate
			attributeCertificate = new AttributeCertificate(test);
			System.out.println("Attribute Certificate: ");
			System.out.println(attributeCertificate.toString(true));
			// verify signature
			try {
				attributeCertificate.verify(acIssuerPublicKey_);
			} catch (SignatureException ex) {
				System.err.println("Signature verification failed: " + ex.getMessage());
				throw ex;
			}
			System.out.println("Signature successfully verified.");
			// validate attributes
			validateAttributes(attributeCertificate);
			// validate extensions
			validateExtensions(attributeCertificate);

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Creates and adds some attribute certificate extensions. The following
	 * extensions are added:
	 * <ul>
	 * <li>iaik.x509.attr.extensions.AuditIdentity
	 * <li>iaik.x509.attr.extensions.NoRevAvail
	 * <li>iaik.x509.attr.extensions.TargetInformation
	 * <li>iaik.x509.attr.extensions.ProxyInfo
	 * </ul>
	 * 
	 * @param attributeCertificate
	 *          the attribute certificate to which the extensions shall be added
	 * 
	 * @throws Exception
	 *           if an error occurs while creating/adding the extensions
	 */
	private void addExtensions(AttributeCertificate attributeCertificate)
	    throws Exception
	{

		// AuditIdentity extension
		byte[] auditValue = { 1, 1, 1, 1, 1, 1, 1, 1 };
		AuditIdentity auditIdentity = new AuditIdentity(auditValue);
		attributeCertificate.addExtension(auditIdentity);

		// NoRevAvail extension
		NoRevAvail noRevAvail = new NoRevAvail();
		attributeCertificate.addExtension(noRevAvail);

		// TargetInformation extension
		TargetInformation targetInformation = new TargetInformation();
		// create and add a TargetName
		GeneralName name = new GeneralName(GeneralName.uniformResourceIdentifier,
		    "www.tugraz.at");
		TargetName targetName = new TargetName(name);
		targetInformation.addTargetElement(targetName);
		// create and add a TargetGroup
		GeneralName groupName = new GeneralName(GeneralName.dNSName, "iaik.at");
		TargetGroup targetGroup = new TargetGroup(groupName);
		targetInformation.addTargetElement(targetGroup);
		// add extension
		attributeCertificate.addExtension(targetInformation);

		// ProxyInfo extension
		ProxyInfo proxyInfo = new ProxyInfo();
		// add two Targets
		TargetName targetName1 = new TargetName(new GeneralName(
		    GeneralName.uniformResourceIdentifier, "http://jce.iaik.tugraz.at"));
		TargetName targetName2 = new TargetName(new GeneralName(
		    GeneralName.uniformResourceIdentifier, "http://jce.iaik.at"));
		// first Targets (ProxySet)
		Targets targets1 = new Targets();
		targets1.setTargets(new Target[] { targetName1, targetName2 });
		proxyInfo.addTargets(targets1);
		TargetName targetName3 = new TargetName(new GeneralName(
		    GeneralName.uniformResourceIdentifier, "http://www.iaik.at"));
		TargetName targetName4 = new TargetName(new GeneralName(
		    GeneralName.uniformResourceIdentifier, "http://www.tugraz.at"));
		// second Targets (ProxySet)
		Targets targets2 = new Targets();
		targets2.addTarget(targetName3);
		targets2.addTarget(targetName4);
		proxyInfo.addTargets(targets2);
		// add extension
		attributeCertificate.addExtension(proxyInfo);

	}

	/**
	 * Validates the extensions contained in this attribute certificate
	 * 
	 * @param attributeCertificate
	 *          the attribute certificate to be validated
	 * 
	 * @exception if
	 *              an exception occurs when validating the attribute certificate
	 */
	private void validateExtensions(AttributeCertificate attributeCertificate)
	    throws Exception
	{
		// get AuditIdentity extension
		AuditIdentity auditIdentity = (AuditIdentity) attributeCertificate
		    .getExtension(AuditIdentity.oid);
		if (auditIdentity != null) {
			System.out.println("AuditIdentity extension included:");
			byte[] auditValue = auditIdentity.getValue();
			System.out.println("Audit value: " + Util.toString(auditValue));
		}

		// get NoRevAvail extension
		NoRevAvail noRevAvail = (NoRevAvail) attributeCertificate
		    .getExtension(NoRevAvail.oid);
		if (noRevAvail != null) {
			System.out
			    .println("No revocation information available for this attribute certificate.");
		}

		// get TargetInformation extension and validate server (must be valid
		// target since accepted by included TargetGroup)
		String serverName = "http://jce.iaik.at";
		GeneralName server = new GeneralName(GeneralName.uniformResourceIdentifier,
		    serverName);

		TargetInformation targetInformation = (TargetInformation) attributeCertificate
		    .getExtension(TargetInformation.oid);
		if (targetInformation != null) {
			System.out.println("TargetInformation extension included.");

			try {
				if (targetInformation.isTargetFor(server)) {
					System.out.println("Server " + serverName
					    + " valid target for this attribute certificate.");
				} else {
					System.out.println("Server " + serverName
					    + " no valid target for this attribute certificate.");
				}
			} catch (TargetException ex) {
				System.out
				    .println("Server object could not be handled by TargetInformation extension: "
				        + ex.getMessage());
				throw ex;
			}
		} else {
			// an attribute certificate that does not contain a TargetInformation is
			// not targeted
			// and can be accepted by any server
			System.out.println("Server " + serverName
			    + " valid target for this attribute certificate.");
		}

		// get ProxyInfo extension
		ProxyInfo proxyInfo = (ProxyInfo) attributeCertificate.getExtension(ProxyInfo.oid);
		if (proxyInfo != null) {
			System.out.println("ProxyInfo extension included.");
			// validate sender/server pair (we assume that we have received the ac
			// from the original sender)
			// proxy check must succeed since sender is holder and server is valid
			// target
			IssuerSerial senderBaseCertificateID = new IssuerSerial(pkcCerts_[0]);
			Holder sender = new Holder();
			sender.setBaseCertificateID(senderBaseCertificateID);
			try {
				if (proxyInfo.checkProxy(sender, server)) {
					System.out.println("Proxy check successfull.");
				} else {
					System.out.println("Proxy check failed.");
				}
			} catch (TargetException ex) {
				System.out
				    .println("Sender/server pair could not be handled by ProxyInfo extension: "
				        + ex.getMessage());
				throw ex;
			}

			// validate a proxy chain
			TargetName proxyTarget1 = new TargetName(new GeneralName(
			    GeneralName.uniformResourceIdentifier, "http://jce.iaik.at"));
			TargetName proxyTarget2 = new TargetName(new GeneralName(
			    GeneralName.uniformResourceIdentifier, "http://jce.iaik.tugraz.at"));
			Target[] proxyChain = { proxyTarget1, proxyTarget2 };
			// proxy chain check must be successful (all in same proxy set):
			try {
				if (proxyInfo.checkProxyChain(proxyChain)) {
					System.out.println("Proxy chain check successfull.");
				} else {
					System.out.println("Proxy chain check failed.");
				}
			} catch (TargetException ex) {
				System.out.println("Proxy chain could not be handled by ProxyInfo extension: "
				    + ex.getMessage());
				throw ex;
			}
		}
	}

	/**
	 * Creates and adds some attributes. The following attributes are added:
	 * <ul>
	 * <li>{@link iaik.x509.attr.attributes.AccessIdentity AccessIdentity}
	 * <li>{@link iaik.x509.attr.attributes.ChargingIdentity ChargingIdentity}
	 * <li>{@link iaik.x509.attr.attributes.Clearance Clearance}
	 * <li>{@link iaik.x509.attr.attributes.Group Group}
	 * <li>{@link iaik.x509.attr.attributes.Role Role}
	 * <li>{@link iaik.x509.attr.attributes.ServiceAuthenticationInfo
	 * ServiceAuthenticationInfo}
	 * </ul>
	 * 
	 * @param attributeCertificate
	 *          the attribute certificate to which the attributes shall be added
	 * 
	 * @throws Exception
	 *           if an error occurs while creating/adding the extensions
	 */
	private void addAttributes(AttributeCertificate attributeCertificate)
	    throws Exception
	{
		try {

			// AccessIdentity
			GeneralName aiService = new GeneralName(GeneralName.uniformResourceIdentifier,
			    "test.iaik.at");
			GeneralName aiIdent = new GeneralName(GeneralName.rfc822Name,
			    "John.Doe@iaik.tugraz.at");
			AccessIdentity accessIdentity = new AccessIdentity(aiService, aiIdent);
			// add AccessIdentity attribute
			attributeCertificate.addAttribute(new Attribute(accessIdentity));

			// Charging Identity
			ObjectID[] ciValues = { ObjectID.iaik };
			ChargingIdentity chargingIdentity = new ChargingIdentity(ciValues);
			// set policy authority
			Name name = new Name();
			name.addRDN(ObjectID.country, "AT");
			name.addRDN(ObjectID.organization, "TU Graz");
			name.addRDN(ObjectID.organizationalUnit, "IAIK");
			name.addRDN(ObjectID.commonName, "IAIK Demo Policy Authority");
			GeneralName policyName = new GeneralName(GeneralName.directoryName, name);
			GeneralNames policyAuthority = new GeneralNames(policyName);
			chargingIdentity.setPolicyAuthority(policyAuthority);
			// add ChargingIdentity attribute
			attributeCertificate.addAttribute(new Attribute(chargingIdentity));

			// Clearance
			ObjectID policyId = new ObjectID("1.3.6.1.4.1.2706.2.2.1.6.1.2");
			Clearance clearance = new Clearance(policyId);
			// class list
			int classList = Clearance.TOP_SECRET;
			clearance.setClassList(classList);
			// register SecurityCategory
			SecurityCategory.register(MySecurityCategory.type, MySecurityCategory.class);
			SecurityCategory[] categories = { new MySecurityCategory("Only for private use!") };
			clearance.setSecurityCategories(categories);
			// add Clearance attribute
			attributeCertificate.addAttribute(new Attribute(clearance));

			// Group
			String gValue1 = "IAIK JavaSecurity";
			String gValue2 = "IAIK PKI";
			String[] gValues = { gValue1, gValue2 };
			Group group = new Group(gValues);
			// add Group attribute
			attributeCertificate.addAttribute(new Attribute(group));

			// Role
			Role role = new Role(roleName_);
			// set role authority to the issuer of the corresponding role
			// specification cert
			role.setRoleAuthority(roleSpecificationCert_);
			// add Role attribute
			attributeCertificate.addAttribute(new Attribute(role));

			// ServiceAuthenticationInfo
			GeneralName service = new GeneralName(GeneralName.uniformResourceIdentifier,
			    "test.iaik.at");
			GeneralName ident = new GeneralName(GeneralName.rfc822Name,
			    "John.Doe@iaik.tugraz.at");
			ServiceAuthenticationInfo serviceAuthInf = new ServiceAuthenticationInfo(service,
			    ident);
			byte[] authInfo = Util.toASCIIBytes("topSecret");
			serviceAuthInf.setAuthInfo(authInfo);
			// add ServiceAuthenticationInformation attribute
			attributeCertificate.addAttribute(new Attribute(serviceAuthInf));

		} catch (Exception ex) {
			System.err.println("Error adding attribute: " + ex.toString());
			throw ex;
		}
	}

	/**
	 * Validates the attributes contained in this attribute certificate
	 * 
	 * @param attributeCertificate
	 *          the attribute certificate to be validated
	 * 
	 * @exception if
	 *              an exception occurs when validating the attribute certificate
	 */
	private void validateAttributes(AttributeCertificate attributeCertificate)
	    throws Exception
	{
		try {

			// get AccessIdentity attribute
			Attribute accessIdentityAttribute = attributeCertificate
			    .getAttribute(AccessIdentity.oid);
			if (accessIdentityAttribute != null) {
				System.out.println("AccessIdentity attribute included.");
				// we know that we have one single AccessIdentity attribute only
				AccessIdentity accessIdentity = (AccessIdentity) accessIdentityAttribute
				    .getAttributeValue();
				// get service and ident names
				GeneralName service = accessIdentity.getService();
				System.out.println("service: " + service);
				GeneralName ident = accessIdentity.getIdent();
				System.out.println("ident: " + ident);
			}

			// get Clearance attribute
			Attribute clearanceAttribute = attributeCertificate.getAttribute(Clearance.oid);
			if (clearanceAttribute != null) {
				// in our example we know that we have a single-valued Clearance
				// attribute only
				Clearance clearance = (Clearance) clearanceAttribute.getAttributeValue();
				// get PolicyId
				ObjectID policyId = clearance.getPolicyId();
				System.out.println("Policy id: " + policyId.getName());
				// class list
				System.out.println("Class list: " + clearance.getClassListBitNames());
				// topSecret?
				if (clearance.isSecurityClassificationValueSet(Clearance.TOP_SECRET)) {
					System.out.println("Security classification is top secret!");
				}
				// get security categories
				SecurityCategory[] securityCategories = clearance.getSecurityCategories();
				for (int i = 0; i < securityCategories.length; i++) {
					System.out.println("SecurityCategory " + securityCategories[i].getName() + ":");
					System.out.println(securityCategories[i].toString());
				}
			}

			// get ChargingIdentity attribute
			Attribute chargingIdentityAttribute = attributeCertificate
			    .getAttribute(ChargingIdentity.oid);
			if (chargingIdentityAttribute != null) {
				System.out.println("ChargingIdentity attribute included.");
				// ChargingIdentity is only allowed to be a single-valued attribute
				ChargingIdentity chargingIdentity = (ChargingIdentity) chargingIdentityAttribute
				    .getAttributeValue();
				// get values
				ASN valueType = chargingIdentity.getASN1TypeOfValues();
				System.out.println("ASN.1 type of values is " + valueType.getName());
				Enumeration values = chargingIdentity.getValues();
				while (values.hasMoreElements()) {
					// we know that we only have used ObjectID values
					ObjectID value = (ObjectID) values.nextElement();
					System.out.println("Responsible for charging is: " + value.getNameAndID());
				}
				// get policy authority, if included
				GeneralNames policyAuthority = chargingIdentity.getPolicyAuthority();
				if (policyAuthority != null) {
					System.out.println("Policy Authority: " + policyAuthority);
				}
			}

			// get Group attribute
			Attribute groupAttribute = attributeCertificate.getAttribute(Group.oid);
			if (groupAttribute != null) {
				System.out.println("Group attribute included.");
				// Group is only allowed to be a single-valued attribute
				Group group = (Group) groupAttribute.getAttributeValue();
				// get values
				ASN valueType = group.getASN1TypeOfValues();
				System.out.println("ASN.1 type of values is " + valueType.getName());
				Enumeration values = group.getValues();
				while (values.hasMoreElements()) {
					// we know that we only have used UTF8String values
					String value = (String) values.nextElement();
					System.out.println("AC holder is member of group: " + value);
				}
				// get policy authority, if included
				GeneralNames policyAuthority = group.getPolicyAuthority();
				if (policyAuthority != null) {
					System.out.println("Policy Authority: " + policyAuthority);
				}
			}

			// get Role attribute
			Attribute roleAttribute = attributeCertificate.getAttribute(Role.oid);
			if (roleAttribute != null) {
				// in our example we know that we have a single-valued Role attribute
				// only
				Role role = (Role) roleAttribute.getAttributeValue();
				// get role name
				GeneralName roleName = role.getRoleName();
				System.out.println("Role name: " + roleName);
				GeneralNames roleAuthority = role.getRoleAuthority();
				if (roleAuthority != null) {
					System.out.println("Role authority: " + roleAuthority);
				}
				if (role.roleSpecifiedBy(roleSpecificationCert_)) {
					System.out.println("Role specification cert issuer is: "
					    + roleSpecificationCert_.getIssuer());
				}
			}

			// get ServiceAuthenticationInfo attribute
			Attribute serviceAuthInfAttribute = attributeCertificate
			    .getAttribute(ServiceAuthenticationInfo.oid);
			if (serviceAuthInfAttribute != null) {
				System.out.println("ServiceAuthenticationInfo attribute included.");
				// we know that we have one single ServiceAuthenticationInformation
				// attribute only
				ServiceAuthenticationInfo serviceAuthInf = (ServiceAuthenticationInfo) serviceAuthInfAttribute
				    .getAttributeValue();
				// get service and ident names
				GeneralName service = serviceAuthInf.getService();
				System.out.println("service: " + service);
				GeneralName ident = serviceAuthInf.getIdent();
				System.out.println("ident: " + ident);
				// get authInfo, if included
				byte[] authInfo = serviceAuthInf.getAuthInfo();
				if (authInfo != null) {
					// we know that we have built the authInfo from a String
					System.out.println("AuthInfo: " + Util.toASCIIString(authInfo));
				}
			}

		} catch (Exception ex) {
			System.err.println("Error validating attribute: " + ex.toString());
			throw ex;
		}
	}

	/**
	 * Main method.
	 * 
	 * @param argv
	 *          the file name to which to save the AttributeCertificate or
	 *          <code>null</code> if the attribute certificate shall not be
	 *          written to a file
	 */
	public static void main(String[] argv) {

		DemoUtil.initDemos();
		(new AttributeCertificateDemo()).start((argv.length == 0) ? null : argv[0]);
	}
}
