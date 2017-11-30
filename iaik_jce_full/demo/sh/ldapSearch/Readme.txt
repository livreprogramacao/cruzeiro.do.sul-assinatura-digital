This directory contains shell scripts for running the Ldap*Search demos.

The required libraries (iaik_jce.jar, iaik_jce_demo.jar, 
jdk11x_update.jar -- for JDK11x) have to be located in 
the ../../../lib directory. If you are using a JDK version < 1.3, 
you also will have to put the JNDI jar files (jndi.jar,
ldap.jar, providerutil.jar; can be downloaded from
from http://java.sun.com/products/jndi) into the ../../../lib directory.

Usage:

LdapCertSearch:
===============

LdapCertSearch <ldapUrl> [options] [<type>]
or
LdapCertSearch <host[:port]> [-b <basedn>] [options] [<type>]

where:
  host:   ldap server host name (e.g. "ldapdemo.iaik.at")
  port:   ldap server port (e.g. 389)
  basedn: base distinguished name (e.g. "c=at")
  type:   "ca"   for ca certificate search only
         |"user" for user (end entity) certificate search only
         |"all"  for ca and user certificate search (default)
options:
 -s "base" | "sub" | "one"
    scope; default: "base"
 -f <filter>
    search filter (e.g. "(cn=John%20Doe)")
 -t <seconds>
    connect timeout in seconds; default: -1 (not specified)
 -l <seconds>
    search time limit in seconds; default: 0 (no time limit)
 -z <max>
    size limit (maximum number of entries to be returned as search result);
               default: 0 (no size limit)
 -o "text" | <dirName>
    output ("text" (default) for output to System.out
            or <dirName> for specifying a directory in the file system
            to which the certificate(s) shall be saved)
 -d "dir" | "flat"
    output type if certificate(s) shall be saved to files:
            "dir" (default) for using sub directories based on the cn,
            "flat" for saving all certificate(s) to the same output directory
 -e "DER" | "PEM"
    encoding format (whether to save certificate(s) in DER (default) or PEM format)


Examples:

LdapCertSearch ldap://ldapdemo.iaik.at/c=at?userCertificate;binary?sub?(cn=John%20Doe) d:/temp/ldapsearch
LdapCertSearch ldapdemo.iaik.at:389 -b "c=at" -s sub -f "(cn=John%20Doe)" -o d:/temp/ldapsearch user


LdapCrlSearch:
==============

LdapCrlSearch <ldapUrl> [options] [<type>]
or
LdapCrlSearch <host[:port]> [-b <basedn>] [options] [<type>]

where:
  host:   ldap server host name (e.g. "ldapdemo.iaik.at")
  port:   ldap server port (e.g. 389)
  basedn: base distinguished name (e.g. "c=at")
  type:   "ca"   for authority revocation list search only
         |"user" for certificate revocation list search only
         |"all"  for arl and crl search (default)
options:
 -s "base" | "sub" | "one"
    scope; default: "base"
 -f <filter>
    search filter (e.g. "null")
 -t <seconds>
    connect timeout in seconds; default: -1 (not specified)
 -l <seconds>
    search time limit in seconds; default: 0 (no time limit)
 -z <max>
    size limit (maximum number of entries to be returned as search result);
               default: 0 (no size limit)
 -o "text" | <dirName>
    output ("text" (default) for output to System.out
            or <dirName> for specifying a directory in the file system
            to which the crl(s) shall be saved)
 -d "dir" | "flat"
    output type if crl(s) shall be saved to files:
            "dir" (default) for using sub directories based on the cn,
            "flat" for saving all crl(s) to the same output directory
 -e "DER" | "PEM"
    encoding format (whether to save crl(s) in DER (default) or PEM format)


Examples:

LdapCrlSearch ldap://ldapdemo.iaik.at/c=at,o=iaik,cn=TestCA?certificateRevocationList;binary?base d:/temp/ldapsearch
LdapCrlSearch ldapdemo.iaik.at:389 -b "c=at,o=iaik,cn=TestCA" -s base -o d:/temp/ldapsearch user


LdapAttributeCertSearch:
=======================

LdapAttrCertSearch <ldapUrl> [options] [<type>]
or
LdapAttrCertSearch <host[:port]> [-b <basedn>] [options] [<type>]

where:
  host:   ldap server host name (e.g. "ldapdemo.iaik.at")
  port:   ldap server port (e.g. 389)
  basedn: base distinguished name (e.g. "c=at")
  type:  "all"  for all attribute certificate search
options:
 -s "base" | "sub" | "one"
    scope; default: "base"
 -f <filter>
    search filter (e.g. "(cn=John%20Doe)")
 -t <seconds>
    connect timeout in seconds; default: -1 (not specified)
 -l <seconds>
    search time limit in seconds; default: 0 (no time limit)
 -z <max>
    size limit (maximum number of entries to be returned as search result);
               default: 0 (no size limit)
 -o "text" | <dirName>
    output ("text" (default) for output to System.out
            or <dirName> for specifying a directory in the file system
            to which the certificate(s) shall be saved)
 -e "DER" | "PEM"
    encoding format (whether to save certificate(s) in DER (default) or PEM format)


Examples:

LdapAttrCertSearch ldap://ldapdemo.iaik.at/c=at?attributeCertificate;binary?sub?(cn=John%20Doe) d:/temp/ldapsearch
LdapAttrCertSearch ldapdemo.iaik.at:389 -b "c=at" -s sub -f "(cn=John%20Doe)" -o d:/temp/ldapsearch 

