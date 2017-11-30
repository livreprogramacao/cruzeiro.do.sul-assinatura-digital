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

import iaik.security.provider.IAIK;
import iaik.utils.Util;
import iaik.x509.net.ldap.LdapURLConnection;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Provider;
import java.security.Security;
import java.util.Locale;

/**
 * Base class of the {@link LdapCertSearch LdapCertSearch}, {@link 
 * LdapAttributeCertSearch LdapAttributeCertSearch} and {@link 
 * LdapCrlSearch LdapCrlSearch} demos that can be used as command
 * line utilities for searching an LDAP directory for certificates,
 * attribute certificates, or crls, respectively. See documentation
 * of the required sub-class for usage instructions.
 * <p>
 * This demo uses {@link iaik.x509.net.ldap.LdapURLConnection
 * LdapURLConnection} which is based on the Java Naming and Directory Interface.
 * For JDK versions &lt;1.3 you will have to put <code>jndi.jar</code>, 
 * <code>ldap.jar</code> and <code>providerutil.jar</code> into your classpath 
 * which can be downloaded from the JNDI homepage at SUN: <a href =
 * "http://java.sun.com/products/jndi" target="_blank">http://java.sun.com/products/jndi</a>.
 * JDK versions &gt;=1.3 already have the JNDI included.
 *
 * @see LdapCertSearch
 * @see LdapCrlSearch
 * @see LdapAttributeCertSearch
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
public abstract class LdapSearch {

	/**
	 * All certificates/crls are saved in the same file directory.
	 */
	private final static int OUTPUT_TYPE_FLAT = 0;

	/**
	 * Certificates/crls are saved in separate directories
	 * with cn as file name.
	 */
	private final static int OUTPUT_TYPE_DIR = 1;

	/**
	 * Use DER encoding.
	 */
	protected final static int DER = 0;

	/**
	 * Use PEM encoding.
	 */
	protected final static int PEM = 1;

	/**
	 * Search for certificate(s).
	 */
	protected final static int CERT_SEARCH = 0;

	/**
	 * Search for attribute certificate(s).
	 */
	protected final static int ATTR_CERT_SEARCH = 1;

	/**
	 * Search for crl(s).
	 */
	protected final static int CRL_SEARCH = 2;

	/**
	 * Search for ca certificates (or authority crls) only.
	 */
	protected final static String CA = "ca";

	/**
	 * Search for user certificates (or certificate revocation lists) only.
	 */
	protected final static String USER = "user";

	/**
	 * Search for all certificates or crls.
	 */
	protected final static String ALL = "all";

	/**
	 * Gets the requested string arg value from args[pos].
	 * 
	 * @param args the argument list
	 * @param pos the position from which to get the value
	 * 
	 * @return the argument value or <code>null</code> if (args.length < pos)
	 *         or args.length is an argument option specifier (starting with "-")
	 */
	private final static String getStringArgValue(String args[], int pos) {
		String arg = null;
		if (args.length >= pos) {
			if (args[pos].startsWith("-") == false) {
				arg = args[pos];
			}
		}
		return arg;
	}

	/**
	 * Gets the requested int arg value from args[pos].
	 * 
	 * @param args the argument list
	 * @param pos the position from which to get the value
	 * 
	 * @return the argument value or <code>-1</code> if (args.length < pos)
	 *         or args.length is an argument option specifier (starting with "-")
	 *         
	 * @exception NumberFormatException if args[pos] does not represent a valid
	 *                                  number        
	 */
	private final static int getIntArgValue(String args[], int pos)
	    throws NumberFormatException
	{
		int intArg = -1;
		if (args.length >= pos) {
			if (args[pos].startsWith("-") == false) {
				intArg = Integer.parseInt(args[pos]);
			}
		}
		return intArg;
	}

	/**
	 * Checks if the given name can be used as file name
	 * (only contains characters A,B,...,Z; a,b,...,z; 0,1,...,9; '.', '-', '_').
	 * If other characters than A,B,...,Z; a,b,...,z; 0,1,...,9; '.', '-', '_'
	 * are included they are replaced by a '_' character.
	 * 
	 * @param name the name to be checked
	 * 
	 * @return the new (maybe) fixed name 
	 */
	private final static String checkFileName(String name) {
		StringBuffer buf = new StringBuffer(name.length());
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			buf.append(isFileChar(c) ? c : '_');
		}
		return buf.toString();
	}

	/**
	 * Checks if the given character can be used in a file name.
	 * We only allow A,B,...,Z; a,b,...,z; 0,1,...,9; 
	 *
	 * @return <code>true</code> if the given character is allowed
	 *         <code>false</code> if not
	 */
	private final static boolean isFileChar(int c) {
		if (c >= 65 && c <= 90) { // A ... Z
			return true;
		}
		if (c >= 97 && c <= 122) { // a ... z
			return true;
		}
		if (c >= 48 && c <= 57) { // 0123456789
			return true;
		}
		if ((c == '.') || (c == '_') || (c == '-')) {
			return true;
		}
		return false;
	}

	static {
		//  register IAIK LDAP URL protocol handler
		System.getProperties().put("java.protocol.handler.pkgs", "iaik.x509.net");
	}

	/***********************
	 * END OF STATIC PART. *
	 ***********************/

	/**
	 * Decides whether to search for certificates (0),
	 * attribute certificates (1) or crls (2).
	 */
	private int searchClass_;

	/**
	 * The directory to which to save the certificates/crls
	 * (maybe <code>null</code> if the certificates/crls shall
	 * be dumped to System.out).
	 */
	private File outDir_;

	/**
	 * Whether to save all certificates/crls into the same
	 * directory or into separate directories based on
	 * cn names (default).
	 */
	private int outDirType_;

	/**
	 * Whether to store certificates/crls in DER (default)
	 * or PEM format.
	 */
	private int encodingFormat_;

	/**
	 * Creates a new LdapSearch object for the given
	 * search type.
	 * 
	 * @param searchType the search type indicating whether to
	 *        search for certificates (0), attribute certificates (1)
	 *        or crls (2)
	 *        
	 * @exception IllegalArgumentException if the given search type
	 *            is not 0 (cert search) or 1 (attribute cert search)
	 *            or 2 (crl search)       
	 */
	protected LdapSearch(int searchType) {
		if ((searchType < CERT_SEARCH) || (searchType > CRL_SEARCH)) {
			throw new IllegalArgumentException("Invalid search type (" + searchType + "). "
			    + "Expecting 0 (cert search), 1 (attribute cert search) "
			    + "or 2 (crl search)!");
		}
		searchClass_ = searchType;
		outDirType_ = OUTPUT_TYPE_DIR; // default: save into separate directories
		encodingFormat_ = DER; // default: use DER encoding
		init();
	}

	/**
	 * Installs the IAIK provider.
	 */
	private void init() {
		String searchName;
		switch (searchClass_) {
		case ATTR_CERT_SEARCH:
			searchName = "LdapAttrCertSearch";
			break;
		case CRL_SEARCH:
			searchName = "LdapCrlSearch";
			break;
		default:
			searchName = "LdapCertSearch";
		}
		System.out.println("*** " + searchName + " of " + IAIK.getVersionInfo() + " ***\n");
		// add IAIK provider
		Security.insertProviderAt(new IAIK(), 1);
		try {
			// install IAIK_ECC provider, if available
			Class eccProviderClass = Class.forName("iaik.security.ecc.provider.ECCProvider");
			Provider eccProvider = (Provider) eccProviderClass.newInstance();
			Security.insertProviderAt(eccProvider, 2);
		} catch (Exception ex) {
			// ignore; ECC provider not available
		}
	}

	/**
	 * Builds an LDAP URL from the given URL String
	 * 
	 * @param url the url of the LDAP server as String
	 * 
	 * @return return the LDAP URL
	 * 
	 * @throws MalformedURLException if the URL cannot be built
	 */
	protected URL buildURL(String url)
	    throws MalformedURLException
	{
		String urlLow = url.toLowerCase();
		if (urlLow.startsWith("ldap://") == false) {
			url = "ldap://".concat(url);
		}
		return new URL(url);
	}

	/**
	 * Parses the given arguments for ldap server url and request properties,
	 * connects to the ldap server and searches it for certificates, crls
	 * or attribute certificates as requested.
	 * 
	 * @param args the ldap server url and request properties specifying 
	 *             (command line) arguments 
	 */
	protected void search(String[] args) {
		if ((args == null) || (args.length == 0)) {
			usage();
		}
		String args0 = args[0].toLowerCase();
		if ((args0.equals("?")) || (args0.equals("help")) || (args0.equals("-?"))
		    || (args0.equals("-help"))) {
			usage();
		}
		// parse ldap url
		String url = args[0];
		URL ldapUrl = null;
		LdapURLConnection con = null;
		// create URL 
		try {
			ldapUrl = buildURL(url);
			con = (LdapURLConnection) ldapUrl.openConnection();
		} catch (IOException ex) {
			error("Invalid url: " + url, ex, false);
		}

		// configure the LdapURLConnection
		con = configure(con, args);

		// now connect to server and get input stream
		InputStream ldapIn = null;
		try {
			System.out.println("Connecting to " + url + "...");
			ldapIn = con.getInputStream();
			System.out.println("Parsing result:");
			readResult(ldapIn, outDir_, encodingFormat_);
		} catch (IOException ex) {
			error("Error reading from " + url + ": " + ex.getMessage(), ex, false);
		} finally {
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
	 * Configures the LdapURLConnection with the given properties.
	 * 
	 * @param con the LdapURLConnection to be configured
	 * @param args the configuration properties 
	 * 
	 * @return the configured LdapURLConnection
	 */
	protected LdapURLConnection configure(LdapURLConnection con, String[] args) {
		int argsLength = args.length;
		String searchType = null;
		// parse options and set connection properties
		if (argsLength > 1) {
			for (int i = 1; i < args.length; i++) {
				String arg = args[i];
				if (arg.startsWith("-")) {
					// option
					if (arg.equals("-b")) {
						// base dn
						String dn = getStringArgValue(args, ++i);
						if (dn == null) {
							error("Missing base dn (-b) argument value!", null, true);
						}
						// set base dn
						try {
							con.setRequestProperty(LdapURLConnection.RP_BASE_DN, dn);
						} catch (IllegalArgumentException ex) {
							error("Invalid base dn: " + dn, ex, true);
						}

					} else if (arg.equals("-s")) {
						// search scope
						String scope = getStringArgValue(args, ++i);
						if (scope == null) {
							error("Missing scope (-s) argument value!", null, true);
						}
						// set search scope
						try {
							con.setRequestProperty(LdapURLConnection.RP_SEARCH_SCOPE, scope);
						} catch (IllegalArgumentException ex) {
							error(ex.getMessage(), null, true);
						}

					} else if (arg.equals("-l")) {
						// search time limit
						try {
							int timeLimit = getIntArgValue(args, ++i);
							if (timeLimit == -1) {
								error("Missing time limit (-l) argument value!", null, true);
							}
							// set time limit
							con.setReadTimeout(timeLimit * 1000);
						} catch (IllegalArgumentException ex) {
							error("Invalid time limit: " + ex.getMessage(), null, true);
						}

					} else if (arg.equals("-t")) {
						// search time limit
						try {
							int connectTimeout = getIntArgValue(args, ++i);
							if (connectTimeout == -1) {
								error("Missing connect timeout (-t) argument value!", null, true);
							}
							// set connect timeout
							con.setConnectTimeout(connectTimeout * 1000);
						} catch (IllegalArgumentException ex) {
							error("Invalid connect timeout: " + ex.getMessage(), null, true);
						}

					} else if (arg.equals("-z")) {
						// size limit
						String sizeLimit = getStringArgValue(args, ++i);
						if (sizeLimit == null) {
							error("Missing size limit (-z) argument value!", null, true);
						}
						// set size limit
						try {
							con.setRequestProperty(LdapURLConnection.RP_SIZE_LIMIT, sizeLimit);
						} catch (IllegalArgumentException ex) {
							error(ex.getMessage(), null, true);
						}
					} else if (arg.equals("-f")) {
						// filter
						String filter = getStringArgValue(args, ++i);
						if (filter == null) {
							error("Missing base filter (-f) argument value!", null, true);
						}
						// set filter
						try {
							con.setRequestProperty(LdapURLConnection.RP_FILTER, filter);
						} catch (IllegalArgumentException ex) {
							error("Invalid filter: " + filter, ex, true);
						}

					} else if (arg.equals("-o")) {
						// output ("text" or directory)
						String out = getStringArgValue(args, ++i);
						if (out == null) {
							error("Missing output (-o) argument value!", null, true);
						}
						if (out.toLowerCase().equals("text") == false) {
							File outDir = new File(out);
							if (outDir.exists() == false) {
								// create output directory
								outDir.mkdir();
							}
							if (outDir.isDirectory() == false) {
								error("Output file \"" + out + "\" is not a directory!", null, false);
							}
							outDir_ = outDir;
						}

					} else if (arg.equals("-d")) {
						if (searchClass_ != ATTR_CERT_SEARCH) {
							// directory output type ("dir" or "flat")
							String dir = getStringArgValue(args, ++i);
							if (dir == null) {
								error("Missing output (-d) argument value!", null, true);
							}
							String dir0 = dir.toLowerCase();
							if (dir0.equals("dir")) {
								outDirType_ = OUTPUT_TYPE_DIR; // save into separate directories
							} else if (dir0.equals("flat")) {
								outDirType_ = OUTPUT_TYPE_FLAT; // save all into same directory
							} else {
								error("Invalid output directory type (\"" + dir
								    + "\"). Expected \"dir\" or \"flat\".", null, true);
							}
						}

					} else if (arg.equals("-e")) {
						// encoding format ("DER" or "PEM")
						String format = getStringArgValue(args, ++i);
						if (format == null) {
							error("Missing encoding (-e) argument value!", null, true);
						}
						String format0 = format.toUpperCase(Locale.US);
						if (format0.equals("DER")) {
							encodingFormat_ = DER;
						} else if (format0.equals("PEM")) {
							encodingFormat_ = PEM;
						} else {
							error("Invalid encoding format (\"" + format
							    + "\"). Expected \"DER\" or \"PEM\".", null, true);
						}

					} else {
						error("Invalid option: \"" + arg + "\"!", null, true);
					}
				} else {
					// searchType ("all", "user" or "ca")
					if (searchType != null) {
						error("Unknown argument \"" + args[i] + "\"!", null, true);
					}
					searchType = args[i];
					try {
						setAttributeProperties(con, searchType);
					} catch (IllegalArgumentException ex) {
						error(ex.getMessage(), null, true);
					}
				}
			}
		}
		if ((searchType == null)
		    && (con.getRequestProperty(LdapURLConnection.RP_ATTRIBUTE_DESCRIPTION) == null)) {
			// default: all
			setAttributeProperties(con, ALL);
		}
		try {
			checkAttributeDescription(con
			    .getRequestProperty(LdapURLConnection.RP_ATTRIBUTE_DESCRIPTION));
		} catch (IllegalArgumentException ex) {
			error(ex.getMessage(), null, true);
		}
		System.out.println("Configuration:\n" + con + "\n");
		return con;
	}

	/**
	 * Sets the attribute properties for the given LdapURLConnection depending
	 * on the specified search type.
	 * 
	 * @param con the LdapURLConnection for which to set the attributes
	 * @param searchType the search type ("ca", "user" or "all")
	 * 
	 * @throws IllegalArgumentException if the given searchType is invalid (not
	 *                                  "ca", "user" or "all")
	 */
	protected abstract void setAttributeProperties(LdapURLConnection con, String searchType)
	    throws IllegalArgumentException;

	/**
	 * Checks if the attribute description is valid for the enabled search class
	 * (certificates (0), attribute certificates (1) or crls (2).
	 * 
	 * @param attributeDescription the attribute description to be checked
	 * 
	 * @exception IllegalArgumentException if the attribute description cannot
	 *                                     be used with the enabled search class
	 */
	protected abstract void checkAttributeDescription(String attributeDescription)
	    throws IllegalArgumentException;

	/**
	 * Reads the result from the given LDAP stream and dumps the received certificates/crls
	 * to System.out or writes them DER or PEM encoded to the given directory.
	 *    
	 * @param ldapIn the stream from which to parse the result
	 * @param outDir the directory to which to save the certificates/crls or <code>null</code>
	 *               if the output shall be dumped to System.out.
	 * @param encodingFormat whether to save the certificates/crls in {@link #DER DER} or
	 *                       {@link #PEM PEM} format
	 *               
	 * @throws IOException if an error occurs when reading and processing the result
	 */
	protected abstract void readResult(InputStream ldapIn, File outDir, int encodingFormat)
	    throws IOException;

	/**
	 * Prints a message describing how to use this LdapSearch program
	 * to System.out.
	 */
	protected void usage() {
		String searchName;
		String name;
		String dn;
		String attributeDescr;
		String scope;
		String filter;
		String searchType;
		switch (searchClass_) {
		case CERT_SEARCH:
			searchName = "LdapCertSearch";
			name = "certificate";
			dn = "c=at";
			attributeDescr = "userCertificate;binary";
			scope = "sub";
			filter = "(cn=John Doe)";
			searchType = "user";
			break;
		case ATTR_CERT_SEARCH:
			searchName = "LdapAttrCertSearch";
			name = "certificate";
			dn = "c=at";
			attributeDescr = "attributeCertificate;binary";
			scope = "sub";
			filter = "(cn=John Doe)";
			searchType = "";
			break;
		case CRL_SEARCH:
			searchName = "LdapCrlSearch";
			name = "crl";
			dn = "c=at,o=iaik,cn=TestCA";
			attributeDescr = "certificateRevocationList;binary";
			scope = "base";
			filter = null;
			searchType = "user";
			break;
		default:
			searchName = "LdapCertSearch";
			name = "certificate";
			dn = "c=at";
			attributeDescr = "userCertificate;binary";
			scope = "sub";
			filter = "(cn=John Doe)";
			searchType = "user";
		}
		System.out.println("Usage:");
		System.out.println(searchName + " <ldapUrl> [options] [<type>]");
		System.out.println("or");
		System.out.println(searchName + " <host[:port]> [-b <basedn>] [options] [<type>]");
		System.out.println("\nwhere:");
		System.out.println("  host:   ldap server host name (e.g. \"ldapdemo.iaik.at\")");
		System.out.println("  port:   ldap server port (e.g. 389)");
		System.out.println("  basedn: base distinguished name (e.g. \"c=at\")");
		if (searchClass_ == CERT_SEARCH) {
			System.out.println("  type:   \"ca\"   for ca certificate search only");
			System.out
			    .println("         |\"user\" for user (end entity) certificate search only");
			System.out
			    .println("         |\"all\"  for ca and user certificate search (default)");
		} else if (searchClass_ == CRL_SEARCH) {
			System.out.println("  type:   \"ca\"   for authority revocation list search only");
			System.out
			    .println("         |\"user\" for certificate revocation list search only");
			System.out.println("         |\"all\"  for arl and crl search (default)");
		} else {
			System.out.println("  type:  \"all\"  for all attribute certificate search");
		}
		System.out.println("options:");
		System.out.println(" -s \"base\" | \"sub\" | \"one\"");
		System.out.println("    scope; default: \"base\"");
		System.out.println(" -f <filter>");
		System.out.println("    search filter (e.g. \"" + filter + "\")");
		System.out.println(" -t <seconds>");
		System.out.println("    connect timeout in seconds; default: -1 (not specified)");
		System.out.println(" -l <seconds>");
		System.out.println("    search time limit in seconds; default: 0 (no time limit)");
		System.out.println(" -z <max>");
		System.out
		    .println("    size limit (maximum number of entries to be returned as search result);");
		System.out.println("               default: 0 (no size limit)");
		System.out.println(" -o \"text\" | <dirName>");
		System.out.println("    output (\"text\" (default) for output to System.out");
		System.out
		    .println("            or <dirName> for specifying a directory in the file system");
		System.out.println("            to which the " + name + "(s) shall be saved)");
		if (searchClass_ != ATTR_CERT_SEARCH) {
			System.out.println(" -d \"dir\" | \"flat\"");
			System.out.println("    output type if " + name + "(s) shall be saved to files:");
			System.out
			    .println("            \"dir\" (default) for using sub directories based on the cn,");
			System.out.println("            \"flat\" for saving all " + name
			    + "(s) to the same output directory");
		}
		System.out.println(" -e \"DER\" | \"PEM\"");
		System.out.println("    encoding format (whether to save " + name
		    + "(s) in DER (default) or PEM format)");
		System.out.println("\n\nExamples:\n");
		System.out.println(searchName + " ldap://ldapdemo.iaik.at/" + dn + "?"
		    + attributeDescr + "?" + scope + ((filter == null) ? "" : ("?" + filter))
		    + " d:/temp/ldapsearch");
		System.out.println(searchName + " ldapdemo.iaik.at:389 -b \"" + dn + "\" -s " + scope
		    + ((filter == null) ? "" : (" -f \"" + filter + "\""))
		    + " -o d:/temp/ldapsearch " + searchType);
		System.out.println();
		Util.waitKey();
		System.exit(-1);
	}

	/**
	 * Determines the name for the file to which to store a certificate/crl.
	 * <p>
	 * If cn is not <code>null</code> and the certificates/crls shall be stored
	 * to cn based sub-directories this method checks if a subdirectory
	 * with the given cn already exists. If no such subdirectory does exist a
	 * new cn subdirectory will be created. Since in this case the certificate/crl
	 * will be saved as first certificate/crl into this directory, the corresponding
	 * file name will be set to "cn_1.cer" (or "cn_1.crl"). However, if
	 * there already exists a subdirectory for the given cn, the file name will
	 * be set to "cn_x.cer" (or "cn_x.crl"), where x is one more than the
	 * number of certs/crls that are already contained in the subdirectory. For
	 * instance, cn may be given as "John Doe" and the base output directory maybe
	 * "d:/ldap/certs". If no subdirectory "John_Doe" is present, it will be created
	 * and the file name for the new certificate will be set to
	 * "d:/ldap/certs/John_Doe/John_Doe_1.cer" to save the certificate as first certificate
	 * into the "John_Doe" subdirectory. If during the ldap search we are getting a 
	 * second certificate with cn "John Doe", it will be saved to 
	 * "d:/ldap/certs/John_Doe/John_Doe_2.cer", the next to "d:/ldap/certs/John_Doe/John_Doe_3.cer",
	 * and so on.
	 * <br>
	 * If cn is not <code>null</code> and all certificates/crls shall be stored
	 * into the same directories (-d option "flat") the cert/crl file is named 
	 * "cert_x_&lt;cn&gt;.cer" (or revocationList_x_&lt;cn&gt;.crl), where x is the total 
	 * number of cert/crl objects loaded so far during the current ldap search
	 * and cn is the common name of the certificate/crl currently processed. In 
	 * this case, if we have a cn "John Doe" and the base output directory is
	 * "d:/ldap/certs", the certificate of John Doe will be saved to a file
	 * "d:/ldap/certs/cert_3_John_Doe.cer" (if we assume that this certificate
	 * is the third certificate that has been downloaded so far).
	 * <br>
	 * If we get a certificate/crl containing no cn in the subject/issuer field, it
	 * will be saved into the base output directory with name "cert_x.cer" (or
	 * revocationList_x.crl), where x is the total number of cert/crl objects loaded
	 * so far during the current ldap search.  
	 * 
	 * @param cn the common name field of the subject of the certificate
	 *           (or of the issuer of the crl) 
	 * @param outDir the base output directory
	 * @param count the number of certs/crls processed so far
	 * 
	 * @return the name of the file to which the current cert/crl shall be stored
	 */
	protected String getFileName(String cn, File outDir, int count) {
		// file extension
		String ext = ".cer";
		// file prefix
		String pre = "cert_";
		if (searchClass_ == CRL_SEARCH) {
			ext = ".crl";
			pre = "revocationList_";
		} else if (searchClass_ == ATTR_CERT_SEARCH) {
			pre = "attributeCert_";
		}
		String fileName = null;
		String dirName = outDir.getAbsolutePath().trim();
		if (!dirName.endsWith(File.separator)) {
			dirName += File.separator;
		}
		if (cn != null) {
			cn = checkFileName(cn);
			if (outDirType_ == OUTPUT_TYPE_DIR) {
				// save to sub directories
				String cnDirName = dirName + cn;
				File cnDirFile = new File(cnDirName);
				int index = 1;
				// do we already have a subdirectory with this cn?
				if (cnDirFile.exists() == false) {
					// create new subdiretory into which to save current cert/crl as first object
					cnDirFile.mkdir();
				} else {
					// check how many objects already contained in this subdiretory
					String[] files = cnDirFile.list();
					// current cert/crl shall be stored as next object
					index = files.length + 1;
				}
				// build file name as "baseOutDir/cn/cn_index.cer" (or revocationList_index.crl)
				fileName = cnDirName + File.separator + cn + "_" + index + ext;
			} else {
				// save all into the same directory
				fileName = dirName + pre + count + "_" + cn + ext;
			}
		} else {
			// no cn ==> store to base output directory
			fileName = dirName + pre + count + ext;
		}
		return fileName;
	}

	/**
	 * Prints an error message to System.out and exits the program.
	 * 
	 * @param message the error message to be printed
	 * @param ex the exception that has been thrown (if not null a 
	 *           stack trace will be printed to System.err)
	 * @param printUsage whether to print usage information or not          
	 */
	protected void error(String message, Exception ex, boolean printUsage) {
		System.out.println(message);
		if (ex != null) {
			ex.printStackTrace();
		}
		if (printUsage) {
			System.out.println();
			usage();
		} else {
			System.exit(-1);
		}
	}

	/**
	 * Prints an error message to System.out but does not exit the program.
	 * 
	 * @param message the error message to be printed
	 */
	protected void error(String message) {
		System.out.println(message);
	}

}
