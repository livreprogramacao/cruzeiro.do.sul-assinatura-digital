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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;

import demo.pkcs.pkcs11.provider.utils.Util;

import iaik.asn1.CodingException;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.GeneralName;
import iaik.asn1.structures.GeneralNames;
import iaik.asn1.structures.Name;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.security.provider.IAIK;
import iaik.utils.KeyAndCertificate;
import iaik.utils.RFC2253NameParserException;
import iaik.x509.X509Certificate;
import iaik.x509.X509ExtensionException;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.attr.Holder;
import iaik.x509.attr.Target;
import iaik.x509.attr.TargetGroup;
import iaik.x509.attr.TargetName;
import iaik.x509.attr.Targets;
import iaik.x509.attr.V2Form;
import iaik.x509.attr.attributes.AccessIdentity;
import iaik.x509.attr.attributes.ChargingIdentity;
import iaik.x509.attr.attributes.Clearance;
import iaik.x509.attr.attributes.Group;
import iaik.x509.attr.attributes.ServiceAuthenticationInfo;
import iaik.x509.attr.extensions.AuditIdentity;
import iaik.x509.attr.extensions.NoRevAvail;
import iaik.x509.attr.extensions.ProxyInfo;
import iaik.x509.attr.extensions.TargetInformation;

/**
 * Signs a X.509 attribute certificate using a token. The actual X.509 specific operations are in
 * the last section of this demo. The hash is calculated outside the token. This implementation just
 * uses raw RSA.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class SignAttributeCertificate {

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 pkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The certificate.
   */
  protected AttributeCertificate certificate_;

  /**
   * The name of the signed file.
   */
  protected OutputStream output_;

  /**
   * The isuer's certificate (optional).
   */
  protected X509Certificate issuerCertificate_;

  /**
   * The holder's certificate.
   */
  protected X509Certificate holderCertificate_;

  /**
   * The key store that represents the token (smart card) contents.
   */
  protected KeyStore tokenKeyStore_;

  /**
   * The signature key. In this case only a proxy object, but the application cannot see this.
   */
  protected PrivateKey signatureKey_;

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public SignAttributeCertificate(OutputStream output, X509Certificate holderCertificate) {
    output_ = output;
    holderCertificate_ = holderCertificate;

    // special care is required during the registration of the providers
    pkcs11Provider_ = new IAIKPkcs11();
    Security.addProvider(pkcs11Provider_); // add IAIK PKCS#11 JCE provider

    iaikSoftwareProvider_ = new IAIK();
    Security.addProvider(iaikSoftwareProvider_); // add IAIK softweare JCE provider

  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }
    String outputFile = args[0];
    X509Certificate holderCertificate = new X509Certificate(new FileInputStream(args[1]));

    OutputStream output = new FileOutputStream(outputFile);

    SignAttributeCertificate demo = new SignAttributeCertificate(output,
        holderCertificate);

    demo.getSignatureKey();
    demo.sign();
    demo.verify();

    output.flush();
    output.close();
    System.out.flush();
    System.err.flush();
  }

  /**
   * This method gets the key stores of all inserted (compatible) smart cards and simply takes the
   * first key-entry. From this key entry it takes the private key and the certificate to retrieve
   * the public key from. The keys are stored in the member variables <code>signatureKey_
   * </code> and <code>verificationKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getSignatureKey() throws GeneralSecurityException, IOException,
      RFC2253NameParserException {
    KeyAndCertificate keyAndCert = Util.getSignatureKeyAndCert(pkcs11Provider_, false);
    signatureKey_ = keyAndCert.getPrivateKey();
    issuerCertificate_ = keyAndCert.getCertificateChain()[0];
  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with <code>signatureKey_</code>.
   * Normally the data would be read from file. The created signature is stored in
   * <code>signature_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If the data file could not be found.
   */
  public void sign() throws GeneralSecurityException, IOException, CodingException {
    System.out.println("##########");

    certificate_ = createPlainAttributeCertificate();

    System.out.print("signing certificate... ");
    certificate_.sign(AlgorithmID.sha1WithRSAEncryption, signatureKey_,
        pkcs11Provider_.getName());
    System.out.println("finished");

    System.out.print("writing DER-encoded certificate to file... ");
    certificate_.writeTo(output_);
    System.out.println("finished");

    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If reading the PKCS#7 file fails.
   */
  public void verify() throws GeneralSecurityException, IOException {
    System.out.println("##########");

    System.out.print("verifying certificate... ");

    if (issuerCertificate_ != null) {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      certificate_.writeTo(buffer);

      InputStream inputStream = new ByteArrayInputStream(buffer.toByteArray()); // the raw data
                                                                                // supplying input
                                                                                // stream
      AttributeCertificate certificate = new AttributeCertificate(inputStream);

      certificate.verify(issuerCertificate_.getPublicKey());

      System.out.println("finished");
    } else {
      System.out.println("Skipped. No issuer certificate specified.");
    }

    System.out.println("##########");
  }

  public AttributeCertificate createPlainAttributeCertificate()
      throws X509ExtensionException, CodingException {

    // create Attribute Certificate
    AttributeCertificate attributeCertificate = new AttributeCertificate();
    // issuer
    Name issuerName = (Name) issuerCertificate_.getSubjectDN();
    V2Form v2Form = new V2Form(issuerName);
    attributeCertificate.setIssuer(v2Form);
    // holder (from base certificate)
    X509Certificate baseCert = holderCertificate_;
    Holder holder = new Holder();
    holder.setBaseCertificateID(baseCert);
    attributeCertificate.setHolder(holder);
    // for this demo we use a ramdomly generated serial number
    attributeCertificate.setSerialNumber(new BigInteger(20, new Random()));
    // validity
    GregorianCalendar c = new GregorianCalendar();
    Date notBeforeTime = c.getTime();
    c.add(Calendar.MONTH, 1);
    Date notAfterTime = c.getTime();
    attributeCertificate.setNotBeforeTime(notBeforeTime);
    attributeCertificate.setNotAfterTime(notAfterTime);
    // add attributes
    addAttributes(attributeCertificate);
    // add some extensions
    addExtensions(attributeCertificate);

    return attributeCertificate;
  }

  /**
   * Creates and adds some attribute certificate extensions. The following extensions are added:
   * <ul>
   * <li>iaik.x509.attr.extensions.AuditIdentity
   * <li>iaik.x509.attr.extensions.NoRevAvail
   * <li>iaik.x509.attr.extensions.TargetInformation
   * <li>iaik.x509.attr.extensions.ProxyInfo
   * </ul>
   * 
   * @param attributeCertificate
   *          the attribute certificate to which the extensions shall be added
   * @throws Exception
   *           if an error occurs while creating/adding the extensions
   */
  private void addExtensions(AttributeCertificate attributeCertificate)
      throws X509ExtensionException {

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
   * Creates and adds some attributes. The following attributes are added:
   * <ul>
   * <li>{@link iaik.x509.attr.attributes.AccessIdentity AccessIdentity}
   * <li>{@link iaik.x509.attr.attributes.ChargingIdentity ChargingIdentity}
   * <li>{@link iaik.x509.attr.attributes.Clearance Clearance}
   * <li>{@link iaik.x509.attr.attributes.Group Group}
   * <li>{@link iaik.x509.attr.attributes.Role Role}
   * <li>{@link iaik.x509.attr.attributes.ServiceAuthenticationInfo ServiceAuthenticationInfo}
   * </ul>
   * 
   * @param attributeCertificate
   *          the attribute certificate to which the attributes shall be added
   * @throws Exception
   *           if an error occurs while creating/adding the extensions
   */
  private void addAttributes(AttributeCertificate attributeCertificate)
      throws CodingException {

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

    // Group
    String gValue1 = "IAIK JavaSecurity";
    String gValue2 = "IAIK PKI";
    String[] gValues = { gValue1, gValue2 };
    Group group = new Group(gValues);
    // add Group attribute
    attributeCertificate.addAttribute(new Attribute(group));

    // ServiceAuthenticationInfo
    GeneralName service = new GeneralName(GeneralName.uniformResourceIdentifier,
        "test.iaik.at");
    GeneralName ident = new GeneralName(GeneralName.rfc822Name, "John.Doe@iaik.tugraz.at");
    ServiceAuthenticationInfo serviceAuthInf = new ServiceAuthenticationInfo(service,
        ident);
    byte[] authInfo = iaik.utils.Util.toASCIIBytes("topSecret");
    serviceAuthInf.setAuthInfo(authInfo);
    // add ServiceAuthenticationInformation attribute
    attributeCertificate.addAttribute(new Attribute(serviceAuthInf));

  }

  public static void printUsage() {
    System.out
        .println("Usage: SignAttributeCertificate <DER-encoded X.509 attribute certificate output file> <holder certificate>");
    System.out
        .println(" e.g.: SignAttributeCertificate attributeCertificate.cer maxmustermann.cer");
  }

}
