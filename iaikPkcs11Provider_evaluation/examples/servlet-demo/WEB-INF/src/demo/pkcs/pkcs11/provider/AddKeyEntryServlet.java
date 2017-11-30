// Copyright (C) 2002 IAIK
// http://jce.iaik.at
//
// Copyright (C) 2003 - 2015 Stiftung Secure Information and
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

package demo.pkcs.pkcs11.provider;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.pkcs.PKCSException;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.keypairgenerators.PKCS11KeyPairGenerationSpec;
import iaik.security.provider.IAIK;
import iaik.utils.Util;
import iaik.x509.X509Certificate;
import iaik.x509.extensions.KeyUsage;
import iaik.x509.extensions.SubjectKeyIdentifier;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Properties;
import java.util.Random;

/**
 * This class shows a short demonstration of how to use this provider
 * in a servlet for digital signing.
 *
 * 
 */
public class AddKeyEntryServlet extends HttpServlet {

	static final long serialVersionUID = 123456789;
	protected IAIKPkcs11 pkcs11Provider_;
	protected IAIK iaikProvider_;
	protected String pkcs11ProviderName_;
	protected char[] userPIN_;
	protected String label_;
	protected int existingEntries;
	protected PrivateKey signatureKey_;
	protected PublicKey verificationKey_;
	protected byte[] signature_;
	protected PrintWriter out;
	protected KeyStore tokenKeyStore;

	/**
	 * The new key-pair.
	 */
	protected KeyPair keyPair_;

	public void init()
	    throws ServletException
	{
		super.init();
		try {
			iaikProvider_ = new IAIK();
			Security.addProvider(iaikProvider_);

		} catch (Throwable ex) {
			ex.printStackTrace();
			throw new ServletException(ex.toString());
		}
		existingEntries = 0;
	}

	public void destroy() {
		super.destroy();
		Security.removeProvider(iaikProvider_.getName());
		Security.removeProvider(pkcs11ProviderName_);
	}

	public void doGet(HttpServletRequest req, HttpServletResponse res)
	    throws ServletException, IOException
	{

		out = res.getWriter();

		out.println("<HTML>");
		out.println("<HEAD><title>Signature</title></HEAD>");
		out.println("<BODY>");
		out.println("<h1>Servlet demo using IAIK PKCS#11-Provider:</h1>");

		String pin = req.getParameter("pin");
		String module = req.getParameter("module");
		String addEntry = req.getParameter("addEntry");
		String signVerify = req.getParameter("signVerify");
		String end = req.getParameter("end");

		try {
			// display keystore entries
			if (pin != null && pin != "") {
				Properties pkcs11ProviderConfig = new Properties();
				//          InputStream configStream = getClass().getClassLoader().getResourceAsStream("iaik/pkcs/pkcs11/provider/IAIKPkcs11.properties");
				//          pkcs11ProviderConfig.load(configStream);
				pkcs11ProviderConfig.put("PKCS11_NATIVE_MODULE", module);
				pkcs11ProviderConfig.put("SLOT_ID", "[0]");
				pkcs11Provider_ = new IAIKPkcs11(pkcs11ProviderConfig);

				Security.addProvider(pkcs11Provider_);
				pkcs11ProviderName_ = pkcs11Provider_.getName();
				userPIN_ = pin.toCharArray();

				tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore");
				if (tokenKeyStore == null) {
					out.println("<p>Got no key store. Ensure that the provider is properly configured and installed.</p>");
					System.exit(0);
				}
				tokenKeyStore.load(null, userPIN_);

				existingEntries = showEntries();

				out.println("<br><p><form method=\"post\" action=\"./ServletDemo\">");
				out.println("<input type=\"hidden\" name=\"addEntry\" value=\"true\">");
				out.println("<input type=\"submit\" value=\"to key generation\">");
				out.println("</form></p>");

				// generate and add key entry
			} else if (addEntry != null && addEntry.equals("true")) {
				out.println("<p>Generating new key entry for demonstration purposes...<p>");
				generateSessionKeyPair();
				label_ = "Testuser" + existingEntries;
				addnewEntry(label_);

				out.println("<br><p><form method=\"post\" action=\"./ServletDemo\">");
				out.println("<input type=\"hidden\" name=\"signVerify\" value=\"true\">");
				out.println("<input type=\"submit\" value=\"signature demonstration\">");
				out.println("</form></p>");

				// sign and verify signature  
			} else if (signVerify != null && signVerify.equals("true")) {
				getSignatureKeyPair(label_);
				sign();
				verify();
				deleteKey(label_);
				out.println("<br><p><form method=\"post\" action=\"./ServletDemo\">");
				out.println("<input type=\"hidden\" name=\"end\" value=\"true\">");
				out.println("<input type=\"submit\" value=\"end\">");
				out.println("</form></p>");

				// go to end of servlet
			} else if (end != null && end.equals("true")) {
				out.println("<p>Servlet demo end.<p>");

				// ask for PIN if not yet provided  
			} else {
				out.println("<p><b>Listing keys and certificates stored on card...</b><p>");
				out.println("<p>Please ensure that a smart card is inserted and enter the name of the PKCS#11 module and the PIN:");
				out.println("<form method=\"post\" action=\"./ServletDemo\">");
				out.println("<table>");
				out.println("<tr><td>PKCS#11-module (e.g. cryptoki.dll):  </td><td><input type=\"text\" name=\"module\"></td></tr>");
				out.println("<tr><td>Card-PIN:  </td><td><input type=\"password\" name=\"pin\"></td><tr>");
				out.println("<tr><td><input type=\"submit\" value=\"OK\"></td></tr>");
				out.println("</table></form>");
			}
		} catch (Exception e) {
			out.println("<p><b>An exception occured.</b><p>");
			e.printStackTrace();
		} finally {
			out.flush();
			out.close();
		}
	}

	public void doPost(HttpServletRequest req, HttpServletResponse res)
	    throws ServletException, IOException
	{
		doGet(req, res);
	}

	/**
	 * Show some information to every keystore entry.
	 * 
	 * @return number of alias entries starting with "Testuser"
	 */
	public int showEntries()
	    throws GeneralSecurityException, IOException
	{
		Enumeration aliases = tokenKeyStore.aliases();
		int existingEntries = 0;

		out.println("<p>This certificates and keys could be found on card:</p>");
		out.println("<table border=\"1\"><tr><th align=left>alias</th><th align=left>details</th></tr>");
		while (aliases.hasMoreElements()) {
			String keyAlias = aliases.nextElement().toString();
			out.println("<tr><td valign=top>" + keyAlias + "</td><td>");
			if (keyAlias.startsWith("Testuser")) existingEntries++;
			if (tokenKeyStore.isKeyEntry(keyAlias)) {
				Key key = tokenKeyStore.getKey(keyAlias, null);
				if (key instanceof PrivateKey) out
				    .println("This is a private key entry with algorithm: " + key.getAlgorithm()
				        + "<br>");
				if (key instanceof PublicKey) out
				    .println("This is a public key entry with algorithm: " + key.getAlgorithm()
				        + "<br>");

				Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
				if (certificateChain != null && certificateChain.length != 0) {
					X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
					out.println("<u>Corresponding certificate:</u><br>");
					out.println("Serial number: "
					    + Util.toString(signerCertificate.getSerialNumber().toByteArray()) + "<br>");
					out.println("Subject DN: " + signerCertificate.getSubjectDN().toString()
					    + "<br>");

					boolean[] keyUsage = signerCertificate.getKeyUsage();
					if (keyUsage != null && keyUsage.length != 0) {
						out.println("Key purpose: " + "<br>");
						if (keyUsage[0]) out.println("digitalSignature" + "<br>");
						if (keyUsage[1]) out.println("nonRepudiation" + "<br>");
						if (keyUsage[2]) out.println("keyEncipherment" + "<br>");
						if (keyUsage[3]) out.println("dataEncipherment" + "<br>");
						if (keyUsage[4]) out.println("keyAgreement" + "<br>");
						if (keyUsage[5]) out.println("keyCertSign" + "<br>");
						if (keyUsage[6]) out.println("cRLSign" + "<br>");
						if (keyUsage[7]) out.println("encipherOnly" + "<br>");
						if (keyUsage[8]) out.println("decipherOnly" + "<br>");
					}
					out.println("</td></tr>");
				}
			}
			if (tokenKeyStore.isCertificateEntry(keyAlias)) {
				X509Certificate cert = (X509Certificate) tokenKeyStore.getCertificate(keyAlias);

				out.println("This is a certificate entry.<br>");
				out.println("Serial number: "
				    + Util.toString(cert.getSerialNumber().toByteArray()) + "<br>");
				out.println("Subject DN: " + cert.getSubjectDN().toString() + "<br>");
				out.println("</td></tr>");
			}
		}
		out.println("</table>");
		return existingEntries;
	}

	/**
	 * This method generates a RSA key-pair. It stores the key-pair in the member
	 * variable <code>keyPair_</code>.
	 *
	 * @exception GeneralSecurityException If anything with the provider fails.
	 */
	public void generateSessionKeyPair()
	    throws GeneralSecurityException
	{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",
		    pkcs11Provider_.getName());

		RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
		privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
		privateKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
		privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
		privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
		privateKeyTemplate.getExtractable().setBooleanValue(Boolean.FALSE);

		RSAPublicKey publicKeyTemplate = new RSAPublicKey();
		publicKeyTemplate.getModulusBits().setLongValue(new Long(1024));
		byte[] publicExponentBytes = { 0x01, 0x00, 0x01 };
		publicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
		publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
		publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
		publicKeyTemplate.getPrivate().setBooleanValue(Boolean.FALSE);

		PKCS11KeyPairGenerationSpec keyPairGenerationSpec = (PKCS11KeyPairGenerationSpec) new PKCS11KeyPairGenerationSpec(
		    publicKeyTemplate, privateKeyTemplate).setUseUserRole(true);

		keyPairGenerator.initialize(keyPairGenerationSpec);

		keyPair_ = keyPairGenerator.generateKeyPair();

	}

	/**
	 * Creating a Public-Key Certificate for the generated public key and add key entry to keystore. 
	 * 
	 * @param label  alias that should be used for the new key entry
	 */
	public void addnewEntry(String label)
	    throws GeneralSecurityException, CodingException
	{
		X509Certificate cert = new X509Certificate();

		Name issuer = new Name();
		issuer.addRDN(ObjectID.country, "AT");
		issuer.addRDN(ObjectID.organization, "IAIK");
		issuer.addRDN(ObjectID.organizationalUnit, "JavaSecurity");

		Name subject = new Name();
		subject.addRDN(ObjectID.surName, "User");
		subject.addRDN(ObjectID.givenName, "Test");
		subject.addRDN(ObjectID.country, "TestCountry");
		subject.addRDN(ObjectID.organization, "TestOrganization");
		subject.addRDN(ObjectID.organizationalUnit, "TestUnit");

		cert.setSerialNumber(new BigInteger(20, new Random()));
		cert.setSubjectDN(subject);
		cert.setIssuerDN(issuer);

		GregorianCalendar date = new GregorianCalendar();

		// ensure that EE certs are in the validity period of CA certs
		if (issuer.equals(subject)) {
			// not before two hours ago
			date.add(Calendar.HOUR_OF_DAY, -2);
			cert.setValidNotBefore(date.getTime());
			date.add(Calendar.MONTH, 12);
		} else {
			// not before one hour ago
			date.add(Calendar.HOUR_OF_DAY, -1);
			cert.setValidNotBefore(date.getTime());
			date.add(Calendar.MONTH, 11);
		}
		cert.setValidNotAfter(date.getTime());

		cert.setPublicKey(keyPair_.getPublic());
		cert.addExtension(new SubjectKeyIdentifier(keyPair_.getPublic()));
		// CA cert: ocsp signing
		KeyUsage ku = new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature);
		cert.addExtension(ku);

		cert.sign(AlgorithmID.sha1WithRSAEncryption, keyPair_.getPrivate(),
		    pkcs11Provider_.getName());

		tokenKeyStore.setKeyEntry(label, keyPair_.getPrivate(), null,
		    new java.security.cert.X509Certificate[] { cert });

		out.println("<p>Key entry added to keystore with alias: " + label + ".");
	}

	/**
	 * get key entry with the specified alias from keystore
	 * 
	 * @param label     alias of the key entry that should be selected
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws UnavailableException
	 */
	public void getSignatureKeyPair(String label)
	    throws GeneralSecurityException, IOException, UnavailableException
	{
		if (tokenKeyStore.isKeyEntry(label)) {
			signatureKey_ = (PrivateKey) tokenKeyStore.getKey(label, null);
			Certificate[] certificateChain = tokenKeyStore.getCertificateChain(label);
			X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
			verificationKey_ = signerCertificate.getPublicKey();
		} else {
			out.println("<p>Signature key with label " + label
			    + " not found. Ensure that a valid card is inserted.<p>");
			throw new UnavailableException("no signature key found");
		}
	}

	/**
	 * This method signs the data in the byte array <code>DATA</code> with
	 * <code>signatureKey_</code>. Normally the data would be read from file.
	 * The created signature is stored in <code>signature_</code>.
	 *
	 * @exception GeneralSecurityException
	 *     If anything with the provider fails.
	 * @exception FileNotFoundException
	 *     If the data file could not be found.
	 */
	public void sign()
	    throws GeneralSecurityException, IOException
	{
		out.println("<p><b>Signing some test data...</b><p>");
		byte[] DATA = "testdaten".getBytes();
		Signature signatureEngine = Signature.getInstance("ExternalSHA256WithRSA",
		    pkcs11Provider_.getName());

		// initialize for signing with our signature key that we got from
		// the keystore
		signatureEngine.initSign(signatureKey_);

		// put the data that should be signed
		out.println("<p>The data to be signed is: \"" + new String(DATA) + "\"<p>");
		signatureEngine.update(DATA);

		// get the signature
		signature_ = signatureEngine.sign();
		out.println("<p>The signature is:");
		out.println(new BigInteger(1, signature_).toString(16));
		out.println("<p>");
	}

	/**
	 * This method verifies the signature stored in <code>signatureKey_
	 * </code>. The verification key used is <code>verificationKey_</code>.
	 * The implementation for the signature algorithm is taken from an
	 * other provider. Here IAIK is used, IAIK is pure software.
	 *
	 * @exception GeneralSecurityException
	 *     If anything with the provider fails.
	 * @exception IOException
	 *     If reading the PKCS#7 file fails.
	 * @exception PKCSException
	 *     If handling the PKCS#7 structure fails.
	 */
	public void verify()
	    throws GeneralSecurityException, IOException, PKCSException
	{
		out.println("<p><b>Verifying signature...</b><p>");
		byte[] DATA = "testdaten".getBytes();
		// get a signature object from the software-only provider for verification
		Signature signatureEngine = Signature.getInstance("ExternalSHA256WithRSA",
		    pkcs11Provider_.getName());

		// initialize for verification with our verification key that we got from
		// the certificate
		signatureEngine.initVerify(verificationKey_);

		// put the original data that claims to be signed
		signatureEngine.update(DATA);

		// verify the signature
		boolean verified = signatureEngine.verify(signature_);

		out.println("<p>Trying to verify signature:<br>");
		if (verified) {
			out.println("The signature was verified successfully<p>");
		} else {
			out.println("The signature was forged or the data was modified!<p>");
		}
	}

	/**
	 * delete generated key to restore initial state
	 * 
	 * @param label   alias of the key entry that should be deleted
	 */
	public void deleteKey(String label)
	    throws GeneralSecurityException, CodingException, IOException
	{
		out.println("<p>Deleting test key entry...<p>");
		if (tokenKeyStore.isKeyEntry(label)) {
			tokenKeyStore.deleteEntry(label);
		}
	}

}
