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

package demo.x509.stream;

import iaik.security.provider.IAIK;
import iaik.utils.Util;
import iaik.x509.RevokedCertificate;
import iaik.x509.X509Certificate;
import iaik.x509.stream.RevokedCertificatesCRLListener;
import iaik.x509.stream.X509CRLStream;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Security;
import java.util.Hashtable;
import java.util.Vector;

import demo.IAIKDemo;

/**
 * This sample demonstrates how to use the CRL stream classes. The CRL stream
 * allows parsing a CRL from a stream on-the-fly; i.e. it does not require
 * storing the CRL in memory. Especially for large CRLs this increases
 * performance and decreases memory consuption significantly.
 * <p>
 * This demo shows the use of these CRL stream classes:<br>
 * <ul>
 * <li>{@link iaik.x509.stream.X509CRLStream}
 * <li>{@link iaik.x509.stream.RevokedCertificatesCRLListener}
 * </ul>
 * 
 * @version File Revision <!-- $$Revision: --> 3 <!-- $ -->
 */
public class X509CRLStreamDemo implements IAIKDemo {

	/**
	 * This method runs the test. In case of an error, it would throw a
	 * <code>java.lang.RuntimeException</code>. <br>
	 * First, it does a setup of input data; i.e. CRL input stream and
	 * certificates. Second, it processes the CRL and gets the result. Last, it
	 * checks if the results are correct.
	 */
	public void start() {
		try {
			// in practice we would get this stream from a network socket or a file
			InputStream crlInputStream = new ByteArrayInputStream(CRL);

			// the issuer certificate of the CRL; usually the CA certificate
			X509Certificate issuerCert = new X509Certificate(ISSUER_CERT);

			// some revoked certificates which we expect to be on the CRL
			X509Certificate revokedCert1 = new X509Certificate(REVOKED_CERT_1);
			X509Certificate revokedCert2 = new X509Certificate(REVOKED_CERT_2);
			X509Certificate revokedCert3 = new X509Certificate(REVOKED_CERT_3);

			// some valid certificates which must not be on the CRL
			X509Certificate validCert1 = new X509Certificate(VALID_CERT_1);
			X509Certificate validCert2 = new X509Certificate(VALID_CERT_2);
			X509Certificate validCert3 = new X509Certificate(VALID_CERT_3);

			// this array would contain all certificates which we are interested in
			// i.e. all certificates which we want to check for revocation
			X509Certificate[] consideredCertificates = new X509Certificate[] { revokedCert1,
			    revokedCert2, revokedCert3, validCert1, validCert2, validCert3 };
			System.out.println("Serial numbers of considered certificates: "
			    + getSerials(consideredCertificates));

			// setup listener with all certificates of interest and public key of CRL
			// signer
			RevokedCertificatesCRLListener listener = new RevokedCertificatesCRLListener(
			    consideredCertificates, issuerCert.getPublicKey());

			// setup the CRL stream handler
			X509CRLStream crlStreamHandler = new X509CRLStream(listener);
			// and let it parse the CRL stream
			crlStreamHandler.parse(crlInputStream);

			// now we get a hashtable which contains all certificates which have been
			// found in the
			// CRL and have also been in the list of considered certificates.
			// the hashtable maps those revoked certificates to RevokedCertificate
			// objects, which
			// provide infos about revocation reason, revocation time, ...
			Hashtable revocationEntriesTable = listener.getRevokedCertificates();

			// now we can investigate the hashtable to see which of the considered
			// certificates
			// are listed on the CRL
			Vector revokedCertificates = new Vector(4);
			for (int i = 0; i < consideredCertificates.length; i++) {
				RevokedCertificate revocationEntry = (RevokedCertificate) revocationEntriesTable
				    .remove(consideredCertificates[i]);
				if (revocationEntry != null) {
					// this considered certificate is listed in the CRL, it is revoked
					revokedCertificates.addElement(consideredCertificates[i]);

					// for this test only, no need to include this in production code
					BigInteger serial = consideredCertificates[i].getSerialNumber();
					System.out.println("Found certificate on CRL with serial number: " + serial);
					if (!serial.equals(revocationEntry.getSerialNumber())) {
						throw new RuntimeException("non-matching CRL entry: " + revocationEntry);
					}
				}
			}

			// all following code is just to verify the results of this test
			// there is no need to include such code in a production environment

			// there should not be any more certificates in the hashtable than the
			// revoked ones of the considered certificate list
			if (!revocationEntriesTable.isEmpty()) {
				// TODO: anything to do? throw exception?
			}

			// now check if we really found all those certificates on the CRL as we
			// expected
			X509Certificate[] revokedCertificatesReferenceList = new X509Certificate[] {
			    revokedCert1, revokedCert2, revokedCert3 };
			for (int i = 0; i < revokedCertificatesReferenceList.length; i++) {
				if (!revokedCertificates.removeElement(revokedCertificatesReferenceList[i])) {
					throw new RuntimeException("Did not find expected certificate on CRL: "
					    + revokedCertificatesReferenceList[i]);
				}
			}

			// check, if there are not other certificates left
			if (revokedCertificates.size() > 0) {
				throw new RuntimeException("Unexpected certificates found on CRL: "
				    + revokedCertificates);
			}

			System.out.println("CRL stream test finished successfully.");
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Starts the CRL stream test.
	 */
	public static void main(String[] argv) {
		Security.insertProviderAt(new IAIK(), 2);
		(new X509CRLStreamDemo()).start();
	}

	/**
	 * Takes certificates and returns their serial numbers as a string in the list
	 * form <i>serial1, serial2, ...</i>. The serial numbers are in decimal
	 * format.
	 * 
	 * @param certs
	 *          the certificates.
	 * @return the string of the serial numbers; e.g.
	 *         <code>3, 7, 24, 97, 244</code>
	 */
	private static String getSerials(X509Certificate[] certs) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < certs.length; i++) {
			if (i != 0) {
				buffer.append(", ");
			}
			buffer.append(certs[i].getSerialNumber());
		}
		return buffer.toString();
	}

	// the prepared sample data follows

	/**
	 * The DER encoded CRL to be parsed.
	 */
	private final byte[] CRL = Util
	    .decodeByteArray("MIICeTCCAWECAQEwDQYJKoZIhvcNAQEFBQAwgb8xCzAJBgNVBAYTAkFUMSYwJAYD"
	        + "VQQKEx1HUkFaIFVOSVZFUlNJVFkgT0YgVEVDSE5PTE9HWTFHMEUGA1UECxM+SW5z"
	        + "aXR1dGUgZm9yIEFwcGxpZWQgSW5mb3JtYXRpb24gUHJvY2Vzc2luZyBhbmQgQ29t"
	        + "bXVuaWNhdGlvbnMxHDAaBgNVBAsTE0lBSUsgS2FybCdzIFRlc3QgQ0ExITAfBgNV"
	        + "BAMTGElBSUsgS2FybCdzIFRlc3QgQ0EgU2lnbhcNMDQwOTMwMDYzMjIzWhcNMDQx"
	        + "MDMwMDYzMjIzWjA8MBICAQ8XDTA0MDkzMDA3MzQyOFowEgIBDhcNMDQwOTMwMDgw"
	        + "NzQ1WjASAgENFw0wNDA5MzAwNjMyMjNaoC8wLTAKBgNVHRQEAwIBATAfBgNVHSME"
	        + "GDAWgBR+DysOzf9/yCuC41/xr9g+3P3wlTANBgkqhkiG9w0BAQUFAAOCAQEANCOM"
	        + "mo2AIm6niXu4fG2qvrQivePtKOokw5UqZVSOUFIOcgUtqmYO60vKSn8i/XTRQcJs"
	        + "IuN5bt0hpIq/nsGxxEPGgCx6BR+4InNmD4Vc3HdvLU+aFpGb3P8JrmAEVMoDMSLz"
	        + "g1zsypdMHhQgfWy8rRhX0t3iybL+4NZrdgghhiEM9TAs4t0jApXm6Sjd8kg4Ax1v"
	        + "sz1STXGtDhgcc4hXOfBnvbWuW/G9ro6Pg3AzvnKnLpaWnYOkV/lASSQjbhU2Vpqm"
	        + "RipOa56cfMbf34426akH01idCub2TSAxxVF6X5Txx9zlp6oIl7DBfKOz/7siMufw"
	        + "hJPyjhepIJ5OzVBpvA==");

	/**
	 * The DER encoded certificate of the CRL issuer (i.e. the CA certificate).
	 */
	private final byte[] ISSUER_CERT = Util
	    .decodeByteArray("MIIEWDCCA0SgAwIBAgIBBjAJBgUrDgMCHQUAMFwxCzAJBgNVBAYTAkFUMRAwDgYD"
	        + "VQQKEwdUVSBHcmF6MQ0wCwYDVQQLEwRJQUlLMQ0wCwYDVQQLEwRLYXJsMR0wGwYD"
	        + "VQQDExRJQUlLIEthcmwncyBUZXN0IFBDQTAeFw0wNDAzMTYxNDUwMDdaFw0wNTA1"
	        + "MDcxNDAwMDBaMIG/MQswCQYDVQQGEwJBVDEmMCQGA1UEChMdR1JBWiBVTklWRVJT"
	        + "SVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPkluc2l0dXRlIGZvciBBcHBsaWVk"
	        + "IEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENvbW11bmljYXRpb25zMRwwGgYD"
	        + "VQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYDVQQDExhJQUlLIEthcmwncyBU"
	        + "ZXN0IENBIFNpZ24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCcVrUz"
	        + "IARlfmDXZB6VBPkUk1bvXq3CtJgYDr5/s+fUBB3egbU7z17GvRGtAQgLfTkIuxzu"
	        + "CcR+z3YTx5Y/FJi0Y7xy28z5CEh9y3y5tY7517teLdmSgeq9Q6sDF7etSacPav/V"
	        + "UXEYjTP62aLqO7gcd9NhldzH6wW/R/dtBUZkoxfG4RTpqSocfzsHO2iiZZH6rFE6"
	        + "7okYvhzbIhi/fxwz9Q0oNtxlTxUoehCYw08BNWkpFtgtAz5mOPhHKUSvF3k5GnV3"
	        + "ZVOVCZzPAIDBeIRPzhJcaQrug0rBsd0ldJS3JJgQxkZ+snE7c/zjWNDYXQPkHsp2"
	        + "PjmZOdKfmjqeOleHAgMBAAGjgcgwgcUwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNV"
	        + "HQ8BAf8EBAMCAcYwEQYJYIZIAYb4QgEBBAQDAgECMEwGA1UdHwRFMEMwQaA/oD2G"
	        + "O2h0dHA6Ly90ZXN0Y29tcHV0ZXIxLmlhaWsuYXQva2FybHMtdGVzdC1jYS9rYXJs"
	        + "c1Rlc3RQQ0EuY3JsMB0GA1UdDgQWBBR+DysOzf9/yCuC41/xr9g+3P3wlTAfBgNV"
	        + "HSMEGDAWgBTJ1vtoWW7ADITCyzKcfQ5vQFxNezAJBgUrDgMCHQUAA4IBAQBtxZxk"
	        + "OU1G8CePYLk3W3d/PD/NMgLt5BQzFcAzLo0a5sBvS/6ubDOsxnlRwzBC3Kq7kQk7"
	        + "5R7nGLC3yi5p5MCSjiXv4RR2kODFquPCqWHIFBwHQiuj9YpsUlESSwSpJAaqkkwU"
	        + "lG/E+tGlYLooZOzgch/eskLEouUnbHRdbFyVa8Rhc43hARI6EUqEtbWoLKrD2Mfd"
	        + "F+dVGXHwCndGzDdQZsGeBXL1E1vE3X6UT6YgINFn0qf4uWwjH/7uL/hehFbVkorj"
	        + "4tnLTQEVSFfujrO9bpoLoMbkWjdXW4bgouQ3H47NMtKRuFXh6da/QfZVetKKpUdm"
	        + "KAiXPz3rzKxT6qRB");

	/**
	 * A DER encoded certificate which has been revoked.
	 */
	private final byte[] REVOKED_CERT_1 = Util
	    .decodeByteArray("MIIEeDCCA2SgAwIBAgIBDTAJBgUrDgMCHQUAMIG/MQswCQYDVQQGEwJBVDEmMCQG"
	        + "A1UEChMdR1JBWiBVTklWRVJTSVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPklu"
	        + "c2l0dXRlIGZvciBBcHBsaWVkIEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENv"
	        + "bW11bmljYXRpb25zMRwwGgYDVQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYD"
	        + "VQQDExhJQUlLIEthcmwncyBUZXN0IENBIFNpZ24wHhcNMDQwOTMwMDU1OTMzWhcN"
	        + "MDUwNTA3MTQwMDAwWjCBjjELMAkGA1UEBhMCQVQxJjAkBgNVBAoTHUdSQVogVU5J"
	        + "VkVSU0lUWSBPRiBURUNITk9MT0dZMUcwRQYDVQQLEz5JbnNpdHV0ZSBmb3IgQXBw"
	        + "bGllZCBJbmZvcm1hdGlvbiBQcm9jZXNzaW5nIGFuZCBDb21tdW5pY2F0aW9uczEO"
	        + "MAwGA1UEAxMFRGVuaXMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJgyYW+z"
	        + "UVIN2NDDyYKqDUES6Ke9y6yGE7bsdjvT5OaYkCHH8G92N3tqFg55fTz9hmO/R2TI"
	        + "wK+Ncb17yw0vNELkcyp7e2pwxqg6LP/bLc1Wl/MCMtFpsys9702fZzTbKx3x+Z2D"
	        + "gEX6C+v93bvMgOwe2YnjTHThUvznWPWq4D/xAgMBAAGjggE4MIIBNDAMBgNVHRMB"
	        + "Af8EAjAAMA4GA1UdDwEB/wQEAwIGwDARBglghkgBhvhCAQEEBAMCBSAwcAYDVR0g"
	        + "BGkwZzBlBgwrBgEEAZUSAQJ7AQEwVTBTBggrBgEFBQcCAjBHGkVUaGlzIGNlcnRp"
	        + "ZmljYXRlIG9ubHkgbWF5IGJlIHVzZWQgZm9yIGRlbW9uc3RyYXRpb24gYW5kIHRl"
	        + "c3QgcHVycG9zZXMwTwYDVR0fBEgwRjBEoEKgQIY+aHR0cDovL3Rlc3Rjb21wdXRl"
	        + "cjEuaWFpay5hdC9rYXJscy10ZXN0LWNhL2thcmxzVGVzdENBU2lnbi5jcmwwHQYD"
	        + "VR0OBBYEFOfJp8G9IIcTNSt9VosJJ6qx6NpzMB8GA1UdIwQYMBaAFH4PKw7N/3/I"
	        + "K4LjX/Gv2D7c/fCVMAkGBSsOAwIdBQADggEBAFMWuWXAsZOfzlQFs7e9yht+vFsG"
	        + "WmJc6vuWefUhlSnjjYaA4bwy0bNbtMqy2vbPjB6R/IPYyiTVyLVAmNLvlbYbVcD8"
	        + "wvj8FbkW4Tk8H1XmcWa2HtcjxFeve2tLnkdlxbdWlgnTC4EStxCXdIw7Bbg0vDY4"
	        + "AzHBtuPIt68WH3VsQQOdWs5yGWo/bvsMbnqv0W5tW9YXU6Q/uInj/5+AusaksbWG"
	        + "5eCQr39xVKHmQA8V5c4H3K5ddzlbfTeSAafJn3EzG3VQEo6Mzh2hydMKXOkJTlLp"
	        + "abuH/pg1Z7KF9oS33LdwOroSqDWxdiLzTCmlnoAtow8FSS1FLSk1ZOy+Kf4=");

	/**
	 * A DER encoded certificate which has been revoked.
	 */
	private final byte[] REVOKED_CERT_2 = Util
	    .decodeByteArray("MIIEdzCCA2OgAwIBAgIBDzAJBgUrDgMCHQUAMIG/MQswCQYDVQQGEwJBVDEmMCQG"
	        + "A1UEChMdR1JBWiBVTklWRVJTSVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPklu"
	        + "c2l0dXRlIGZvciBBcHBsaWVkIEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENv"
	        + "bW11bmljYXRpb25zMRwwGgYDVQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYD"
	        + "VQQDExhJQUlLIEthcmwncyBUZXN0IENBIFNpZ24wHhcNMDQwOTMwMDYwMzU0WhcN"
	        + "MDUwNTA3MTQwMDAwWjCBjTELMAkGA1UEBhMCQVQxJjAkBgNVBAoTHUdSQVogVU5J"
	        + "VkVSU0lUWSBPRiBURUNITk9MT0dZMUcwRQYDVQQLEz5JbnNpdHV0ZSBmb3IgQXBw"
	        + "bGllZCBJbmZvcm1hdGlvbiBQcm9jZXNzaW5nIGFuZCBDb21tdW5pY2F0aW9uczEN"
	        + "MAsGA1UEAxMEUnVzczCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA331Conmz"
	        + "u/XtyhdirLYpmOVGWvieR5r8rdFOPWYoPXyrk7D4sJHgtEV1uLGXAPh5OvUPQ7Xt"
	        + "9aOvX3nMnjLAo+wqtxJOAwl3v+ipEOmWYbIGoC9SulrNwjcoHkQwSEYaurog4+Bd"
	        + "TndfQKGodgGERRqQsP01lg/MLATql2cum3cCAwEAAaOCATgwggE0MAwGA1UdEwEB"
	        + "/wQCMAAwDgYDVR0PAQH/BAQDAgbAMBEGCWCGSAGG+EIBAQQEAwIFIDBwBgNVHSAE"
	        + "aTBnMGUGDCsGAQQBlRIBAnsBATBVMFMGCCsGAQUFBwICMEcaRVRoaXMgY2VydGlm"
	        + "aWNhdGUgb25seSBtYXkgYmUgdXNlZCBmb3IgZGVtb25zdHJhdGlvbiBhbmQgdGVz"
	        + "dCBwdXJwb3NlczBPBgNVHR8ESDBGMESgQqBAhj5odHRwOi8vdGVzdGNvbXB1dGVy"
	        + "MS5pYWlrLmF0L2thcmxzLXRlc3QtY2Eva2FybHNUZXN0Q0FTaWduLmNybDAdBgNV"
	        + "HQ4EFgQUUSBpZJ0J0p3r6eh4k0a97p2F+18wHwYDVR0jBBgwFoAUfg8rDs3/f8gr"
	        + "guNf8a/YPtz98JUwCQYFKw4DAh0FAAOCAQEAFAyoIFJmomrrotHcGLPdvvYDpLl9"
	        + "LTz836yDeeEFbyB8wntFB1s6R665YPTQmZHTcpQhGSDltAtJx5ITAVDDd/qxtYAE"
	        + "BNjutaKXt1kFQnrQzwsBY531IAABXgGrCSFQQfE79SnLthYNNruBtEDlAXud0hKx"
	        + "v05mgJc2o2slEFpmSHAJbuhCqQuC6n574Mm+7B0OTx7yUWwql7YE5yGoYt6oKN2G"
	        + "FPlwBHBo0qqsNKyt2WH67l7PkeAO9+jtz5uZD8+b0kacVeUwEGtQHvCSXefLgH/j"
	        + "h9hGJ/fphRpZ7tYHPNR0xHdIf+FCCNpjo94awWd8njNo3xyVp7DsJl629g==");

	/**
	 * A DER encoded certificate which has been revoked.
	 */
	private final byte[] REVOKED_CERT_3 = Util
	    .decodeByteArray("MIIEeTCCA2WgAwIBAgIBDjAJBgUrDgMCHQUAMIG/MQswCQYDVQQGEwJBVDEmMCQG"
	        + "A1UEChMdR1JBWiBVTklWRVJTSVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPklu"
	        + "c2l0dXRlIGZvciBBcHBsaWVkIEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENv"
	        + "bW11bmljYXRpb25zMRwwGgYDVQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYD"
	        + "VQQDExhJQUlLIEthcmwncyBUZXN0IENBIFNpZ24wHhcNMDQwOTMwMDYwMDQyWhcN"
	        + "MDUwNTA3MTQwMDAwWjCBjzELMAkGA1UEBhMCQVQxJjAkBgNVBAoTHUdSQVogVU5J"
	        + "VkVSU0lUWSBPRiBURUNITk9MT0dZMUcwRQYDVQQLEz5JbnNpdHV0ZSBmb3IgQXBw"
	        + "bGllZCBJbmZvcm1hdGlvbiBQcm9jZXNzaW5nIGFuZCBDb21tdW5pY2F0aW9uczEP"
	        + "MA0GA1UEAxMGU3RldmVuMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgt/Cl"
	        + "unWr5d9pt+WaLzDAZRg5AKwR2s6I4U0bCmxYvSseAWVvmyI7311tHujhRNFFg1Ki"
	        + "p7RW8dqk2FnJVKlJfAA0qo5mWLtucahPB9i+uU0KEngYZGbEx9nN+DIbtLkP2Bzu"
	        + "C68jjsc52tEk7hzeqysxeDgu13GyeOCjKXEGlwIDAQABo4IBODCCATQwDAYDVR0T"
	        + "AQH/BAIwADAOBgNVHQ8BAf8EBAMCBsAwEQYJYIZIAYb4QgEBBAQDAgUgMHAGA1Ud"
	        + "IARpMGcwZQYMKwYBBAGVEgECewEBMFUwUwYIKwYBBQUHAgIwRxpFVGhpcyBjZXJ0"
	        + "aWZpY2F0ZSBvbmx5IG1heSBiZSB1c2VkIGZvciBkZW1vbnN0cmF0aW9uIGFuZCB0"
	        + "ZXN0IHB1cnBvc2VzME8GA1UdHwRIMEYwRKBCoECGPmh0dHA6Ly90ZXN0Y29tcHV0"
	        + "ZXIxLmlhaWsuYXQva2FybHMtdGVzdC1jYS9rYXJsc1Rlc3RDQVNpZ24uY3JsMB0G"
	        + "A1UdDgQWBBTqEJfm+JThvn+Jvc1/gHF5gjXj9TAfBgNVHSMEGDAWgBR+DysOzf9/"
	        + "yCuC41/xr9g+3P3wlTAJBgUrDgMCHQUAA4IBAQB5oBAQsJlVIgEbxU7esIrZMr5m"
	        + "Uue4cSeCS6nkeh9hT/qwr7c7TCDoRO7ynlXvKG6sMilZfSA0xeDyZ81jOU97M8V8"
	        + "LkKUkcmW7y3rf98o15qD8sFTH/0aJLNcyoFrJOQo9uicWRcYU1kLc+UZplKprS6J"
	        + "y0GmjhKItio6ZiJ8bBIh3rsZLKDP1AKZUcedvapbHOPjg9gyNzVN0WpPlcgxdq6O"
	        + "8iJAslnjGBH39h9kb+96TLdU2xf8xzCugJUEIucFBcnERzA8DpdMZlSB2faIuLh7"
	        + "bv/HWpGS+jJDt9ADNn4w/31N7cxca11LbeQdBekgqtdU9gMQUL7B4LRalS2i");

	/**
	 * A DER encoded certificate which has not been revoked.
	 */
	private final byte[] VALID_CERT_1 = Util
	    .decodeByteArray("MIIEdzCCA2OgAwIBAgIBEjAJBgUrDgMCHQUAMIG/MQswCQYDVQQGEwJBVDEmMCQG"
	        + "A1UEChMdR1JBWiBVTklWRVJTSVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPklu"
	        + "c2l0dXRlIGZvciBBcHBsaWVkIEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENv"
	        + "bW11bmljYXRpb25zMRwwGgYDVQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYD"
	        + "VQQDExhJQUlLIEthcmwncyBUZXN0IENBIFNpZ24wHhcNMDQwOTMwMDYwNzIwWhcN"
	        + "MDUwNTA3MTQwMDAwWjCBjTELMAkGA1UEBhMCQVQxJjAkBgNVBAoTHUdSQVogVU5J"
	        + "VkVSU0lUWSBPRiBURUNITk9MT0dZMUcwRQYDVQQLEz5JbnNpdHV0ZSBmb3IgQXBw"
	        + "bGllZCBJbmZvcm1hdGlvbiBQcm9jZXNzaW5nIGFuZCBDb21tdW5pY2F0aW9uczEN"
	        + "MAsGA1UEAxMEQ2FybDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAvFndv1ap"
	        + "VIO6o+zfuo59KFzZd/6hherWdDovBK0sNAUhHyuV/z/c/oET28SQh/cGnrp9NXVA"
	        + "4Pu0n1RcuEBNYuVJOl939uMysX+P7q+b9o/6UBLwEVokjFsMFROSeUnIgkIcDYR/"
	        + "ho2sRx/uQ9Rnj57dHXf+aipM/SRVwg3i190CAwEAAaOCATgwggE0MAwGA1UdEwEB"
	        + "/wQCMAAwDgYDVR0PAQH/BAQDAgbAMBEGCWCGSAGG+EIBAQQEAwIFIDBwBgNVHSAE"
	        + "aTBnMGUGDCsGAQQBlRIBAnsBATBVMFMGCCsGAQUFBwICMEcaRVRoaXMgY2VydGlm"
	        + "aWNhdGUgb25seSBtYXkgYmUgdXNlZCBmb3IgZGVtb25zdHJhdGlvbiBhbmQgdGVz"
	        + "dCBwdXJwb3NlczBPBgNVHR8ESDBGMESgQqBAhj5odHRwOi8vdGVzdGNvbXB1dGVy"
	        + "MS5pYWlrLmF0L2thcmxzLXRlc3QtY2Eva2FybHNUZXN0Q0FTaWduLmNybDAdBgNV"
	        + "HQ4EFgQU3evmTGd8YyJieJ6F7iQ4dboE3p8wHwYDVR0jBBgwFoAUfg8rDs3/f8gr"
	        + "guNf8a/YPtz98JUwCQYFKw4DAh0FAAOCAQEAOSxHsu2DFL+3a2cuADSFU4ekdhBl"
	        + "pjDlzAaVLeLjBSNjQHyzpUt0H6hFL6bZO4JXYhQKFTjFRx/DEhjtuhSOF0azzh0g"
	        + "AuqEnNYCTBAwejnz6OjWFvA2C9+ojWyJ1HuJ5plnxRSDisv+UJHw81q7skmeHcjU"
	        + "eRfhoe1yAe4Syo23cpYqa1rL04ZXUdtzbGq3XPEBjjBhZGDknLWO2nETjCUppNBD"
	        + "0FsywQ7XZ5xEhANKZ1BLbqrxHx1qkngx+4A8cHVziDeuO3KPd+c8+8PYJ4TdCWrq"
	        + "sPx2S3d1EBkB4wMzxH93nSIIuHg+f55AAV2De0D47pA+m7XqOe1cnhH82g==");

	/**
	 * A DER encoded certificate which has not been revoked.
	 */
	private final byte[] VALID_CERT_2 = Util
	    .decodeByteArray("MIIEeDCCA2SgAwIBAgIBEDAJBgUrDgMCHQUAMIG/MQswCQYDVQQGEwJBVDEmMCQG"
	        + "A1UEChMdR1JBWiBVTklWRVJTSVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPklu"
	        + "c2l0dXRlIGZvciBBcHBsaWVkIEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENv"
	        + "bW11bmljYXRpb25zMRwwGgYDVQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYD"
	        + "VQQDExhJQUlLIEthcmwncyBUZXN0IENBIFNpZ24wHhcNMDQwOTMwMDYwNTEzWhcN"
	        + "MDUwNTA3MTQwMDAwWjCBjjELMAkGA1UEBhMCQVQxJjAkBgNVBAoTHUdSQVogVU5J"
	        + "VkVSU0lUWSBPRiBURUNITk9MT0dZMUcwRQYDVQQLEz5JbnNpdHV0ZSBmb3IgQXBw"
	        + "bGllZCBJbmZvcm1hdGlvbiBQcm9jZXNzaW5nIGFuZCBDb21tdW5pY2F0aW9uczEO"
	        + "MAwGA1UEAxMFUGV0ZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKF4u0LY"
	        + "aDzxUnKdosy/mM7PJFBxksS/lOlwtIHpnKYua6DxHFnYyXAQ+iJVfPJJfWSoi5KK"
	        + "79b/yIS3VGGS/eOdpnuiXPYX/0FnUVRpDWnaWbQTZh0bjfO2SoGIFvq9iGwV5CsS"
	        + "bQTC5fbQV3tcAr4LBrMcrEclDgfWhvMHPut3AgMBAAGjggE4MIIBNDAMBgNVHRMB"
	        + "Af8EAjAAMA4GA1UdDwEB/wQEAwIGwDARBglghkgBhvhCAQEEBAMCBSAwcAYDVR0g"
	        + "BGkwZzBlBgwrBgEEAZUSAQJ7AQEwVTBTBggrBgEFBQcCAjBHGkVUaGlzIGNlcnRp"
	        + "ZmljYXRlIG9ubHkgbWF5IGJlIHVzZWQgZm9yIGRlbW9uc3RyYXRpb24gYW5kIHRl"
	        + "c3QgcHVycG9zZXMwTwYDVR0fBEgwRjBEoEKgQIY+aHR0cDovL3Rlc3Rjb21wdXRl"
	        + "cjEuaWFpay5hdC9rYXJscy10ZXN0LWNhL2thcmxzVGVzdENBU2lnbi5jcmwwHQYD"
	        + "VR0OBBYEFKPZXSPL3QrEZR+CTSOMXkPD1nn0MB8GA1UdIwQYMBaAFH4PKw7N/3/I"
	        + "K4LjX/Gv2D7c/fCVMAkGBSsOAwIdBQADggEBABDpqw8/npg5SbLsXyrcXJMIvXM9"
	        + "Dq1g8+jU/a190lpOzW+Mq6h+t1oMDyTv6Co9fIuS2OyvdEVH+l7zKEnTW0fcGRsj"
	        + "amPQjyRjgdE6Smj+zxT1R0GRmLr+TSSLB3MnjajgvW/0ROXGTpb3u+oSnJv12yh9"
	        + "acHDANeQZeEA9SQcoJHOuwcelWoyd5qUQMLhPswgnl8PDvJnJkpXTXdqqJxEg5rZ"
	        + "wsk1M8AsO3efPuk7iUVN6TC3zdHJju2MRdd4vNjq5j9LDtY1/rPkI7BGxkizk/V5"
	        + "EC/eO5PAFIQEn2qyy1NR3rL4uTUV9/XSfVRBtYHR0B8xsPJIY83SHNekWHU=");

	/**
	 * A DER encoded certificate which has not been revoked.
	 */
	private final byte[] VALID_CERT_3 = Util
	    .decodeByteArray("MIIEdjCCA2KgAwIBAgIBETAJBgUrDgMCHQUAMIG/MQswCQYDVQQGEwJBVDEmMCQG"
	        + "A1UEChMdR1JBWiBVTklWRVJTSVRZIE9GIFRFQ0hOT0xPR1kxRzBFBgNVBAsTPklu"
	        + "c2l0dXRlIGZvciBBcHBsaWVkIEluZm9ybWF0aW9uIFByb2Nlc3NpbmcgYW5kIENv"
	        + "bW11bmljYXRpb25zMRwwGgYDVQQLExNJQUlLIEthcmwncyBUZXN0IENBMSEwHwYD"
	        + "VQQDExhJQUlLIEthcmwncyBUZXN0IENBIFNpZ24wHhcNMDQwOTMwMDYwNjMzWhcN"
	        + "MDUwNTA3MTQwMDAwWjCBjDELMAkGA1UEBhMCQVQxJjAkBgNVBAoTHUdSQVogVU5J"
	        + "VkVSU0lUWSBPRiBURUNITk9MT0dZMUcwRQYDVQQLEz5JbnNpdHV0ZSBmb3IgQXBw"
	        + "bGllZCBJbmZvcm1hdGlvbiBQcm9jZXNzaW5nIGFuZCBDb21tdW5pY2F0aW9uczEM"
	        + "MAoGA1UEAxMDUm9uMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLfEaYjWfh"
	        + "e8/oKDV/U/+Jzy7DcI2Ms4TgvOC7t3l3u97pDTxlKYuMtrkCnEKRRacY6vU8cNx2"
	        + "tD8pszG16EQVByGFT0HAenMJ7odUkStYqrCjBKTcTfgPyeJ0O7BSo8J1VkKAnpmp"
	        + "qJnoebmMJ5B19SDKABBa9s2aoJFsxt45ywIDAQABo4IBODCCATQwDAYDVR0TAQH/"
	        + "BAIwADAOBgNVHQ8BAf8EBAMCBsAwEQYJYIZIAYb4QgEBBAQDAgUgMHAGA1UdIARp"
	        + "MGcwZQYMKwYBBAGVEgECewEBMFUwUwYIKwYBBQUHAgIwRxpFVGhpcyBjZXJ0aWZp"
	        + "Y2F0ZSBvbmx5IG1heSBiZSB1c2VkIGZvciBkZW1vbnN0cmF0aW9uIGFuZCB0ZXN0"
	        + "IHB1cnBvc2VzME8GA1UdHwRIMEYwRKBCoECGPmh0dHA6Ly90ZXN0Y29tcHV0ZXIx"
	        + "LmlhaWsuYXQva2FybHMtdGVzdC1jYS9rYXJsc1Rlc3RDQVNpZ24uY3JsMB0GA1Ud"
	        + "DgQWBBRH0uODAs5xMngtLJqo4kgsYCbt7zAfBgNVHSMEGDAWgBR+DysOzf9/yCuC"
	        + "41/xr9g+3P3wlTAJBgUrDgMCHQUAA4IBAQCDpwtXJ5jCARcJokUBpnVKNqYupRo6"
	        + "RH3PUHjlen56siqAYGodZ9vzG0KsDTRFHoOLU5kuKIFBgM54uU+whH3Z1E1n2ipG"
	        + "uWtHqiSs1UjUoNmj8QOCjnFdRVkpcWVQixwBNA3B43CBGNEElGkpHz82JamQlYFx"
	        + "yujAANLRiALnGBZCzImhQkd82aOUpbdRVP0f0rsihshMbBgqD9Nbk8jz7ZD/L7kE"
	        + "rj0+ZXuGaQADU/O9EA5hUC1cgtctuk99s+hWj94SwddZiH8LHVoQZHVpG7X5nCll"
	        + "NrFOTpUIIaAmBl0tbPhMd35gTRYPcKX4mSx3SQ+DRxUoeC2lqEJQr1Na");

}
