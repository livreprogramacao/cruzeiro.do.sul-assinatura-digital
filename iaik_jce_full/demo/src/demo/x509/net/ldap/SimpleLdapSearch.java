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

package demo.x509.net.ldap;

import iaik.x509.X509CRL;
import iaik.x509.X509Certificate;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.net.ldap.LdapURLConnection;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;

import demo.util.DemoUtil;

/**
 * This class demonstrates how to use the IAIK-JCE {@link 
 * iaik.x509.net.ldap.LdapURLConnection LdapURLConnection} implementation
 * for searching an LDAP directory for certificates, attribute certificates
 * and crls.
 * <br>
 * For running this demo, the url, ca and subject names used by this 
 * example shall be replaced by real world ldap urls and ca/subject
 * names.
 * <p>  
 * This demo uses {@link iaik.x509.net.ldap.LdapURLConnection
 * LdapURLConnection} which is based on the Java Naming and Directory Interface.
 * For JDK versions &lt;1.3 you will have to put <code>jndi.jar</code>, 
 * <code>ldap.jar</code> and <code>providerutil.jar</code> into your classpath 
 * which can be downloaded from the JNDI homepage at SUN: <a href =
 * "http://java.sun.com/products/jndi" target="_blank">http://java.sun.com/products/jndi</a>.
 * JDK versions &gt;=1.3 already have the JNDI included.
 *
 * @see java.net.URL
 * @see java.net.URLConnection
 * @see iaik.x509.X509Certificate
 * @see iaik.x509.attr.AttributeCertificate
 * @see iaik.x509.X509CRL
 * @see iaik.x509.stream.X509CRLStream
 * @see iaik.x509.net.ldap.Handler
 * @see iaik.x509.net.ldap.LdapURLStreamHandlerFactory
 * @see iaik.x509.net.ldap.LdapURLConnection
 */
public class SimpleLdapSearch {

	/**
	 * Default constructor.
	 */
	public SimpleLdapSearch() {
		super();
	}

	/**
	 * Demonstrates how to use the IAIK-JCE {@link iaik.x509.net.ldap.LdapURLConnection
	 * LdapURLConnection} implementation for searching an LDAP directory for
	 * certificates. The ldap host and entity cn names used in this example
	 * maybe replaced by real-world server and cn names.
	 * 
	 * @exception IOException if an I/O error occurs when searching the ldap
	 */
	public void searchForCertificates()
	    throws IOException
	{

		// ldap server url
		String ldapUrl = "ldap://demoldap.iaik.at/";
		URL url = new URL(ldapUrl);
		LdapURLConnection con = (LdapURLConnection) url.openConnection();
		// base dn 
		con.setRequestProperty(LdapURLConnection.RP_BASE_DN, "c=at");
		// search for end enity certificates
		con.setRequestProperty(LdapURLConnection.RP_ATTRIBUTE_DESCRIPTION,
		    LdapURLConnection.AD_USER_CERTIFICATE);
		// search subtree
		con.setRequestProperty(LdapURLConnection.RP_SEARCH_SCOPE,
		    LdapURLConnection.SEARCH_SCOPE_SUBTREE);
		// set filter
		con.setRequestProperty(LdapURLConnection.RP_FILTER, "(cn=Joe TestUser)");
		// connect to the ldap server and read result
		InputStream ldapIn = null;
		// we have searched for certificates
		int i = 0;
		try {
			ldapIn = con.getInputStream();
			// do until we get an EOF
			while (true) {
				// parse next certificate from stream
				try {
					X509Certificate cert = new X509Certificate(ldapIn);
					System.out.println("Cert[" + ++i + "]: " + cert.getSubjectDN());
				} catch (CertificateException ex) {
					System.err.println("Error parsing certificate: " + ex.toString());
				}
			}
		} catch (EOFException ex) {
			// ignore; finished
		} catch (IOException ex) {
			System.err.println("I/O error when reading ldap response: " + ex.toString());
			throw ex;
		} finally {
			// close ldap input stream to disconnect from server
			if (ldapIn != null) {
				try {
					ldapIn.close();
				} catch (IOException ex) {
					// ignore
				}
			}
		}
		System.out.println("Totally read " + i + " certificates");

	}

	/**
	 * Demonstrates how to use the IAIK-JCE {@link iaik.x509.net.ldap.LdapURLConnection
	 * LdapURLConnection} implementation for searching an LDAP directory for
	 * attribute certificates. The ldap host and entity cn names used in this example
	 * maybe replaced by real-world server and cn names.
	 * 
	 * @exception IOException if an I/O error occurs when searching the ldap
	 */
	public void searchForAttributeCertificates()
	    throws IOException
	{

		// ldap server url
		String ldapUrl = "ldap://demoldap.iaik.at/";
		URL url = new URL(ldapUrl);
		LdapURLConnection con = (LdapURLConnection) url.openConnection();
		// base dn 
		con.setRequestProperty(LdapURLConnection.RP_BASE_DN, "c=at");
		// search for end enity certificates
		con.setRequestProperty(LdapURLConnection.RP_ATTRIBUTE_DESCRIPTION,
		    LdapURLConnection.AD_ATTRIBUTE_CERTIFICATE);
		// search subtree
		con.setRequestProperty(LdapURLConnection.RP_SEARCH_SCOPE,
		    LdapURLConnection.SEARCH_SCOPE_SUBTREE);
		// set filter
		con.setRequestProperty(LdapURLConnection.RP_FILTER, "(cn=Joe TestUser)");
		// connect to the ldap server and read result
		InputStream ldapIn = null;
		// we have searched for certificates
		int i = 0;
		try {
			ldapIn = con.getInputStream();
			// do until we get an EOF
			while (true) {
				// parse next certificate from stream
				try {
					AttributeCertificate cert = new AttributeCertificate(ldapIn);
					System.out.println("Cert[" + ++i + "]: " + cert.getHolder());
				} catch (CertificateException ex) {
					System.err.println("Error parsing certificate: " + ex.toString());
				}
			}
		} catch (EOFException ex) {
			// ignore; finished
		} catch (IOException ex) {
			System.err.println("I/O error when reading ldap response: " + ex.toString());
			throw ex;
		} finally {
			// close ldap input stream to disconnect from server
			if (ldapIn != null) {
				try {
					ldapIn.close();
				} catch (IOException ex) {
					// ignore
				}
			}
		}
		System.out.println("Totally read " + i + " certificates");
	}

	/**
	 * Demonstrates how to use the IAIK-JCE {@link iaik.x509.net.ldap.LdapURLConnection
	 * LdapURLConnection} implementation for searching an LDAP directory for
	 * some particular certificate revocation list referenced by the ldap
	 * url. The ldap url used in this example maybe replaced by a real-world
	 * url pointing to a crl on an ldap server.
	 * 
	 * @exception IOException if an I/O error occurs when searching the ldap
	 */
	public void searchForCertificateRevocationList()
	    throws IOException
	{

		// ldap url where crl is located
		URL url = new URL(
		    "ldap://ldapdemo.iaik.at/cn=IAIK%20RSA%20Test%20CA,ou=Java%20Security,o=IAIK,c=at?certificateRevocationList;binary");
		// (the parameters given in the url also could be set as request properties)
		LdapURLConnection con = (LdapURLConnection) url.openConnection();
		// connect to the ldap server and read result
		InputStream ldapIn = null;
		// we have searched for a crl
		try {
			ldapIn = con.getInputStream();
			// we only expect one crl
			X509CRL crl = new X509CRL(ldapIn);
			System.out.println(crl);
		} catch (CRLException ex) {
			System.err.println("Error parsing crl: " + ex.toString());
			throw new IOException(ex.toString());
		} catch (IOException ex) {
			System.err.println("I/O error when reading ldap response: " + ex.toString());
			throw ex;
		} finally {
			// close ldap input stream to disconnect from server
			if (ldapIn != null) {
				try {
					ldapIn.close();
				} catch (IOException ex) {
					// ignore
				}
			}
		}

	}

	/**
	 * Main method.
	 */
	public static void main(String[] args) {
		// install IAIK provider
		DemoUtil.initDemos();
		// register ldap protocol handler
		System.getProperties().put("java.protocol.handler.pkgs", "iaik.x509.net");

		SimpleLdapSearch ldapSearch = new SimpleLdapSearch();

		// search for certificates
		try {
			ldapSearch.searchForCertificates();
		} catch (IOException ex) {
			System.err.println("Error searching for certificates: " + ex.toString());
		}

		// search for attribute certificates
		try {
			ldapSearch.searchForAttributeCertificates();
		} catch (IOException ex) {
			System.err.println("Error searching for attribute certificates: " + ex.toString());
		}

		// search for attribute certificates
		try {
			ldapSearch.searchForCertificateRevocationList();
		} catch (IOException ex) {
			System.err.println("Error searching for crl: " + ex.toString());
		}

	}

}
