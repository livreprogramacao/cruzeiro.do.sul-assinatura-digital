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

import iaik.utils.Util;
import iaik.x509.attr.AttributeCertificate;
import iaik.x509.net.ldap.LdapURLConnection;

import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;

/**
 * IAIK {@link iaik.x509.net.ldap.LdapURLConnection LdapURLConnection}
 * demo that can be used as command line utility for searching an 
 * LDAP directory for attribute certificates.
 * <p>
 * When running this demo you at least have to specify the url of
 * the ldap server you want to search for attribute certificates:
 * <pre>  
 * LdapAttributeCertSearch &lt;ldapUrl&gt; [options] [&lt;type&gt;]
 * or
 * LdapAttributeCertSearch &lt;host[:port]&gt; [-b &lt;basedn&gt;] [options] [&lt;type&gt;]
 * </pre>
 * The ldap url has to follow the string format given in RFC 2255
 * (extensions are not supported and therefore ignored unless they 
 * contain a critical extension, in which case an exception is thrown):
 * <pre>
 * ldapurl    = scheme "://" [hostport] ["/"
 *              [dn ["?" [attributes] ["?" [scope]
 *              ["?" [filter] ["?" extensions]]]]]]
 * </pre>
 * For instance:
 * <pre>
 * LdapAttributeCertSearch ldap://ldapdemo.iaik.at/c=at?attributeCertificate;binary?sub?(cn=John%20Doe)
 * </pre>
 * Optionally you can specify a search type (the only supported type for attribute
 * certificate search is "all" to search for all attribute certificates; this also 
 * is the default value and therefore must not be specified explicitly). 
 * <p> 
 * The following table lists the options that can be specified when running this
 * <code>LdapAttributeCertSearch</code> program:
 * <p>
 * <table border="1">
 *  <tr>
 *   <td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>
 *   <td><div align="center"><b>Description</b></div></td>
 *   <td><div align="center"><b>Value/Example</b></div></td>
 *   <td><div align="center"><b>Default Value</b></div></td>
 *  </tr>
 *  <tr>
 *   <td><div align="center" width="5"><b>-b</b></div></td>
 *   <td><div align="center">base distinguished name</div></td>
 *   <td><div align="center">"c=at"</div></td>
 *   <td><div align="center">&nbsp;</div></td>
 *  </tr>
 *  <tr>
 *   <td><div align="center" width="5"><b>-s</b></div></th>
 *   <td><div align="center">search scope</div></td>
 *   <td><div align="center">"base" for base object search<br>
 *                           "one"  for one level search<br>
 *                           "sub"  for subtree search</div></td>
 *   <td><div align="center">"base"</div></td>                            
 *  </tr>
 *  <tr>
 *   <td><div align="center" width="5"><b>-f</b></div></th>
 *   <td><div align="center">search filter</div></td>
 *   <td><div align="center">"(uid=JDoe)"<br>
 *                           "(cn=John Doe)"</div></td>
 *   <td><div align="center">&nbsp;</div></td>                           
 *  </tr>
 *  <tr>
 *   <td><div align="center" width="5"><b>-t</b></div></th>
 *   <td><div align="center">connect timeout (in seconds)</div></td>
 *   <td><div align="center">30</div></td>
 *   <td><div align="center">-1 (not specified)</div></td>                           
 *  </tr>
 *  <tr>
 *   <td><div align="center" width="5"><b>-l</b></div></th>
 *   <td><div align="center">search time limit (in seconds)</div></td>
 *   <td><div align="center">60</div></td>
 *   <td><div align="center">0 (no time limit)</div></td>                           
 *  </tr>
 *  <tr>
 *   <td><div align="center" width="5"><b>-z</b></div></th>
 *   <td><div align="center">size limit (maximum number of entries to be returned as
 *                           search result<SUP><FONT SIZE=-2>*</FONT></SUP>)</div></td>
 *   <td><div align="center">2</div></td>
 *   <td><div align="center">0 (return all entries)</div></td>                           
 *  </tr>   
 *  <tr>
 *   <td><div align="center" width="5"><b>-o</b></div></th>
 *   <td><div align="left">output; either <code>"text"</code> to dump the certificate(s) to System.out,
 *                                 or the name of a directory in the file system
 *                                 to which the certificate(s) shall be saved;
 *                                 <b>Attention! The output directory is created automatically
 *                                  without asking for user confirmation!</b>)</div></td>
 *   <td><div align="center">"text"<br>
 *                           "d:/temp/ldapsearch/attrcerts"</div></td>
 *   <td><div align="center">"text"</div></td>                           
 *  </tr>  
 *  <tr>
 *   <td><div align="center" width="5"><b>-e</b></div></th>
 *   <td><div align="left">encoding format (whether to save certificate(s) in DER (default)
 *                         or PEM format)</td>
 *   <td><div align="center">"DER"<br>
 *                           "PEM"</div></td>
 *   <td><div align="center">"DER"</div></td>                           
 *  </tr>           
 * </table>
 * <FONT SIZE=-2><SUP>*</SUP></FONT><FONT SIZE=-1>The number of certificate
 * objects actually returned by the search procedure must not be equal to
 * the requested size limit. Of course, it may be lower than the size limit 
 * (since the size limit specifies the maximum number of entries to be returned 
 * as search result). However, the number of received certificate objects even
 * might be higher than the size limit: for instance, if you have searched for
 * certificates and have set the size limit to 2, you may get two entries as
 * result of the search, and each of them may hold any number of certificates 
 * (e.g. the first may contain one certificate attribute and the second may
 * contain two certificate attributes giving totally three certificates).</FONT>
 * <p>
 * Examples:
 * <pre>
 * LdapAttrCertSearch ldap://ldapdemo.iaik.at/c=at?attributeCertificate;binary?sub?(cn=John%20Doe) d:/temp/ldapsearch
 * 
 * LdapAttrCertSearch ldapdemo.iaik.at:389 -b "c=at" -s sub -f "(cn=John Doe)" -o d:/temp/ldapsearch 
 * </pre>
 * Both examples above will search an ldap server running at "ldapdemo.iaik.at", port 389, for
 * attribute certificates belonging to entries with cn "John Doe". The search will cover the whole
 * subtree under (and including) the base dn "c=at". The certificates will
 * be saved to the file system into the directory "d:/temp/ldapsearch". 
 * <p>
 * This demo uses {@link iaik.x509.net.ldap.LdapURLConnection
 * LdapURLConnection} which is based on the Java Naming and Directory Interface.
 * For JDK versions &lt;1.3 you will have to put <code>jndi.jar</code>, 
 * <code>ldap.jar</code> and <code>providerutil.jar</code> into your classpath 
 * which can be downloaded from the JNDI homepage at SUN: <a href =
 * "http://java.sun.com/products/jndi" target="_blank">http://java.sun.com/products/jndi</a>.
 * JDK versions &gt;=1.3 already have the JNDI included.
 * 
 * @see LdapSearch
 * @see LdapCrlSearch
 * @see LdapCertSearch
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
public class LdapAttributeCertSearch extends LdapSearch {

	/**
	 * Default constructor.
	 */
	public LdapAttributeCertSearch() {
		super(ATTR_CERT_SEARCH);
	}

	/**
	 * Sets the attribute properties for the given LdapURLConnection.
	 * The only attribute description for attribute certificate search
	 * is "attributeCertificate;binary".
	 * 
	 * @param con the LdapURLConnection for which to set the attributes
	 * @param searchType the search type("all")
	 * 
	 * @throws IllegalArgumentException if the given searchType is invalid 
	 *                                  (not "all")
	 */
	protected void setAttributeProperties(LdapURLConnection con, String searchType)
	    throws IllegalArgumentException
	{

		if (con == null) {
			throw new NullPointerException("LdapURLConnection must not be null!");
		}
		if (searchType.equals(ALL)) {
			con.addRequestProperty(LdapURLConnection.RP_ATTRIBUTE_DESCRIPTION,
			    LdapURLConnection.AD_ATTRIBUTE_CERTIFICATE);
		} else {
			throw new IllegalArgumentException("Invalid search type: \"" + searchType + "\". "
			    + "Must be \"all\".");
		}

	}

	/**
	 * Checks if the attribute description is valid for attribute certificate search.
	 * 
	 * @param attributeDescription the attribute description to be checked
	 * 
	 * @exception IllegalArgumentException if the attribute description cannot
	 *                                     be used for attribute certificate search
	 */
	protected void checkAttributeDescription(String attributeDescription)
	    throws IllegalArgumentException
	{
		if (attributeDescription != null) {
			String ad = attributeDescription.toLowerCase();
			if (ad.indexOf("attributecertificate") == -1) {
				throw new IllegalArgumentException("Invalid attribute description \""
				    + attributeDescription + "\". Only attribute certificate search supported.");
			}
		}
	}

	/**
	 * Reads the result from the given LDAP stream and dumps the received attribute
	 * certificates to System.out or writes them DER or PEM encoded to the given directory.
	 *    
	 * @param ldapIn the stream from which to parse the result
	 * @param outDir the directory to which to save the attribute certificates or <code>null</code>
	 *               if the output shall be dumped to System.out.
	 * @param encodingFormat whether to save the attribute certificates in {@link #DER DER} or
	 *                       {@link #PEM PEM} format
	 *                                      
	 * @throws IOException if an error occurs when reading and processing the result
	 */
	protected void readResult(InputStream ldapIn, File outDir, int encodingFormat)
	    throws IOException
	{
		int i = 0;
		int count = 0;
		try {
			// do until we get an EOF
			while (true) {
				try {
					// parse next certificate from stream
					AttributeCertificate cert = new AttributeCertificate(ldapIn);
					// save to file?
					if (outDir != null) {
						System.out.print("Loading attribute certificate " + ++i);
						// save to file
						FileOutputStream fos = null;
						String fileName = getFileName(null, outDir, i);
						try {
							fos = new FileOutputStream(fileName);
							if (encodingFormat == DER) {
								cert.writeTo(fos);
							} else {
								fos.write(Util.toPemArray(cert));
							}
						} catch (Exception ex) {
							error("Error saving cert to " + fileName + ": " + ex.toString());
						} finally {
							if (fos != null) {
								try {
									fos.close();
								} catch (IOException ex) {
									// ignore
								}
							}
						}
					} else {
						// dump to System.out only
						System.out.println("Certificate [" + ++i + "]:");
						System.out.println(cert.toString(true));
						System.out.println();
						System.out.println(iaik.utils.Util.toPemString(cert));
						System.out.println();
					}
					++count;
				} catch (CertificateException ex) {
					error("Error parsing certificate no. " + ++i + ": " + ex.toString());
				}
			}
		} catch (EOFException ex) {
			// ignore
		}
		System.out.println("\nTotally got " + count + " certificate(s)");
	}

	/**
	 * Main method. Starts the LDAP attribute certificate search.
	 * 
	 * @param args program arguments like ldap url, base dn, search scope...
	 */
	public static void main(String[] args) {
		LdapAttributeCertSearch ldapSearch = new LdapAttributeCertSearch();
		ldapSearch.search(args);
	}

}
