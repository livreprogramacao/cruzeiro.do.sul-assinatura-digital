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

package demo.pkcs;

import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Name;
import iaik.security.provider.IAIK;
import iaik.utils.Util;
import iaik.x509.X509Certificate;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;

/**
 * This demo shows how to use the PKCS12 KeyStore Implementation. An
 * demonstration PKCS#12-file is used to show how to retrieve and add key and
 * certificate entries.
 */
public class PKCS12KeyStoreDemo {

	/**
	 * The new certificate generated with
	 * {@link #generateKeyAndCertificate(String)}.
	 */
	private X509Certificate[] certs_;

	/**
	 * The new key generated with {@link #generateKeyAndCertificate(String)}.
	 */
	private PrivateKey privKey_;

	/**
	 * This method is the entry point for this demo.
	 * 
	 * @throws Exception
	 *           if anything in the demo fails.
	 */
	private void demoKeyStore()
	    throws Exception
	{
		// from file, this may look like this
		// InputStream fis = new FileInputStream("demoKeyStore.p12");
		// in this example, we read it from a byte array
		final InputStream fis = new ByteArrayInputStream(DEMO_PKCS12_FILE);

		final String password = "password";

		// load KeyStore
		final KeyStore store = KeyStore.getInstance("PKCS12", "IAIK");
		store.load(fis, password.toCharArray());

		// list existing entries
		System.out.println("Listing KeyStore as read from the prepared demo store");
		listEntries(store);

		// create new KeyStore
		final KeyStore storeNew = KeyStore.getInstance("PKCS12", "IAIK");
		storeNew.load(null, null);

		// write entries to new KeyStore
		final Enumeration aliases = store.aliases();
		while (aliases.hasMoreElements()) {
			final String alias = (String) aliases.nextElement();
			storeNew.setKeyEntry(alias, store.getKey(alias, "password".toCharArray()),
			    "password".toCharArray(), store.getCertificateChain(alias));
		}

		// create new certificate and key
		generateKeyAndCertificate("Max Mustermann");

		// add entry
		final String newEntryName = "Max";
		storeNew.setKeyEntry(newEntryName, privKey_, "password".toCharArray(), certs_);

		// test if new entry was added successfully
		if (!storeNew.containsAlias("Max")) {
			throw new KeyStoreException("Entry has not been added successfully!");
		}

		// list entries again
		System.out.println("Listing KeyStore after adding entry " + newEntryName);

		listEntries(storeNew);

		FileOutputStream os = null;
		// save KeyStore
		try {
			os = new FileOutputStream("demoKeyStoreNew.p12");
			storeNew.store(os, "password".toCharArray());
		} finally {
			if (os != null) {
				try {
					os.close();
				} catch (final IOException e) {
					// ignore
				}
			}
		}

		// test if KeyStore was stored
		try {
			InputStream is = null;

			try {
				is = new FileInputStream("demoKeyStoreNew.p12");
				store.load(is, "password".toCharArray());
			} finally {
				if (is != null) {
					try {
						is.close();
					} catch (IOException e) {
						// ignore
					}
				}
			}
		} catch (final CertificateException ce) {
			throw new CertificateException("KeyStore could not be saved!");
		}
	}

	/**
	 * Print all entries of the given store to standard out.
	 * 
	 * @param store
	 *          The store to dump.
	 * @throws Exception
	 *           if reading some entries fails.
	 */
	private void listEntries(KeyStore store)
	    throws Exception
	{
		System.out.println("Entries in KeyStore:");
		final Enumeration aliases = store.aliases();
		int entrynumber = 1;
		while (aliases.hasMoreElements()) {
			final String alias = (String) aliases.nextElement();
			System.out.println("Entry " + entrynumber + ": " + alias);
			entrynumber++;
		}
		System.out.println();
	}

	/**
	 * Generate a new key-pair and a self-signed certificate.
	 * 
	 * @param subjectCommonName
	 *          The common name of the subject.
	 * @throws Exception
	 *           if key-pair generation or certificate signing fails.
	 */
	private void generateKeyAndCertificate(String subjectCommonName)
	    throws Exception
	{
		final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "IAIK");
		generator.initialize(1024);
		final KeyPair kp = generator.generateKeyPair();

		final Name issuer = new Name();
		issuer.addRDN(ObjectID.country, "AT");
		issuer.addRDN(ObjectID.organization, "TestCompany");
		issuer.addRDN(ObjectID.organizationalUnit, "CA");
		issuer.addRDN(ObjectID.commonName, "Test Certificate Agency");

		final Name userSubject = new Name();
		userSubject.addRDN(ObjectID.country, "AT");
		userSubject.addRDN(ObjectID.organization, "your company");
		userSubject.addRDN(ObjectID.organizationalUnit, "your department");
		userSubject.addRDN(ObjectID.commonName, subjectCommonName);

		final X509Certificate[] newIaikCert = new X509Certificate[1];
		newIaikCert[0] = new X509Certificate();
		newIaikCert[0].setSerialNumber(BigInteger.valueOf(new Date().getTime()));
		newIaikCert[0].setSubjectDN(userSubject);
		newIaikCert[0].setPublicKey(kp.getPublic());
		newIaikCert[0].setIssuerDN(issuer);

		final GregorianCalendar date = new GregorianCalendar();
		date.add(Calendar.DATE, -1);
		newIaikCert[0].setValidNotBefore(date.getTime());

		date.add(Calendar.MONTH, 6);
		newIaikCert[0].setValidNotAfter(date.getTime());

		privKey_ = kp.getPrivate();

		newIaikCert[0].sign(AlgorithmID.sha1WithRSAEncryption, privKey_);

		certs_ = newIaikCert;
	}

	/**
	 * This main method runs this demo.
	 * 
	 * @param arg
	 *          ignored.
	 * @throws Exception
	 *           if anything in the demo fails.
	 */
	public static void main(String arg[])
	    throws Exception
	{
		Security.insertProviderAt(new IAIK(), 2);
		(new PKCS12KeyStoreDemo()).demoKeyStore();
		System.out.println("PKCS#12 demo finished successfully");
		iaik.utils.Util.waitKey();
	}

	/**
	 * This is the content of the sample PKCS#12 file.
	 */
	private static final byte[] DEMO_PKCS12_FILE = Util
	    .decodeByteArray("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCBAAwgDCABgkqhkiG9w0BBwGggCSABIIE\r\n"
	        + "ADCCBpUwggHLBgsqhkiG9w0BDAoBAqCCAYUwggGBMBsGCiqGSIb3DQEMAQMwDQQI\r\n"
	        + "ydgEPK41YQ8CAQEEggFgPDWUj7wG+4PtFHgOncecgVMaJUOeL2hOSWFdBQSnRmqB\r\n"
	        + "Jp6BBkxbMzMuxN42xXd8IERXc5Xujvy6I30F1QE7VVdlprXYg0AAgXSsIA0bZ85z\r\n"
	        + "KWIY5WHjaVHs6hwOfphNNKqvRxK0Sy+wvHneMaM74OBKPEW2f7POeZFoNko48D4F\r\n"
	        + "jkI/4LOCZQ4onoDv7cQUJaaABOGWq8WvM0Y5lSBbV3ZJyl62mPbyTjuxG09eJhc0\r\n"
	        + "d438/apLPtiUqUJQiWfcuAuU4bTdjYsVEkbKbcET9EdvQTBSlt3BS7zaVTbqPd/m\r\n"
	        + "fmuIFeyzNjt9EuIBmZryITHDt02PvOEoWUmiKNoUc63nFhT1cAtDK89qN5ATzdzI\r\n"
	        + "UAOsYtgPa90XP7Nr7B3fZh0+h3gXVFSClbA4fpLIMgxbMIlIMILrn2dSNCQ/fnW2\r\n"
	        + "0FSMekKj3Jpd6fToXX2RiuP2iwPzol4+BKSuZyyHNTEzMBMGCSqGSIb3DQEJFDEG\r\n"
	        + "HgQAQwBBMBwGCSqGSIb3DQEJFTEPBA0xMTczMzU5NDE3NzA1MIIBzQYLKoZIhvcN\r\n"
	        + "AQwKAQKgggGFMIIBgTAbBgoqhkiG9w0BDAEDMA0ECAGXo6aTFIAKAgEBBIIBYLmQ\r\n"
	        + "m42jmINP4pfWdO46gGBwUx92uhTxkRFdQ0ctxY8bda87A0h8Xsgc0ty+EG2UY2F5\r\n"
	        + "IOZt8KCIE/pfvOTGmx80JHiPsBek3oJBJwQVc8Jj2qIMQPHefq/arPWNiUDXRLpA\r\n"
	        + "fgwFzl40JgUtOG3L4FZwuTGv2JocmEHSb4cmWE3mV2PE58IYOjK41H9BWsBLFNwk\r\n"
	        + "En7qdcXav/Dly7vYGfIpLanNfD/6N0TZMNpsyjfBDKYExcqHalXOa/a8fkoGiQFP\r\n"
	        + "qPsSbGcd1+VnxO0WNjOVhU5MXw3eHiZDEqLs0RajPZh2WcMCGuYr0VZ8OqhTl58d\r\n"
	        + "bKTAvCJguLG7onQYDH3ndF8u0NUT15XsnWp6RTUhDJ4YT6vTYRhtvBsmo5EdDX2D\r\n"
	        + "22UDROrjAa/tHEzLsvmXgTlGKqqf78jyrV504nvhsX57jdHZv+nzLJXv0G289+8Z\r\n"
	        + "yEV9gNUoMTPYeMcEwHoxNTAVBgkqhkiG9w0BCRQxCB4GAEIAbwBiMBwGCSqGSIb3\r\n"
	        + "DQEJFTEPBA0xMTczMzU5NDE3NDM5MIIC8QYLKoZIhvcNAQwKAQKgggKlMIICoTAb\r\n"
	        + "BgoqhkiG9w0BDAEDMA0ECJywWuYwgQFPAgEBBIICgEoGYeHgrthGeykSBIIEABPQ\r\n"
	        + "9AKe3q/YcBYr6dUMW2agOCEgjIMKBIICmYcvM5K9YR2xkBju2sOYHRk2cPAbBmqN\r\n"
	        + "d+QzocN2vJt/2MrB8aX5PGDaJzt3vke+wvchL/B5xw2ErPhHRTJjU4uPupwpgVJ/\r\n"
	        + "B3KIS8vIIAvj71yC8V2HAUBOJvRZHD/cTEk2tYlx+KqIVGKGY5i5kt/AgpE/DhI7\r\n"
	        + "XSK8qzrMslLszMc2pA3HrDeg+OSz9NWpHnZ91zjdVY/C2zlCsXz0RKX1OS1C8ixo\r\n"
	        + "Iebp9ejtgl97luTFtxl4y20cczNFMk7jD4HhY9KWZLzDCtYDlSj7NRm0kG+dGUZ6\r\n"
	        + "CPXOqjWwFOFCZqaoCLWqjwbfVMCL73H6qp1WoxQKeQF9UX5Q8oxeyuGr0yf0J4PU\r\n"
	        + "AxmHLvFqODlLiWmsyIY3QaO1Rno9N3fgKiV7rUDRmqILwKPAssOCJfD5X1UU6bQt\r\n"
	        + "iShZP/1QAfmqiBb0DlG8/QCzSLHWh6pxI8hAbfFMUXFXbkSGr7HhIjdi2nw4MO5a\r\n"
	        + "MfE7LDXcb3jHHT1bJCXSAR0FGDkk94+Eb8h45AMbY/BTsUi/QT52T57EW8D3D7pN\r\n"
	        + "TdXeeIT9oQ1kNQqJurepNVMiM9+87CarPuBpqLb46KuGqsa18OZ7dc/cYHvIDOEM\r\n"
	        + "NHmrj7s1Y3eO1DfTDHm9+vUW9EVRdoGIOYWHoq5zhHhhg6e566U5VgEBmZy9cvBI\r\n"
	        + "yBN+hQJrL1W73EypHGPoyZOvVw3Li0A2hV6hs6e8RmmxpFGO87y2MyuuaAKbs92E\r\n"
	        + "lUMGh3+tU3ktnuRpAcU9Cdd3sL7d0KisAlRUNC/d9dC7NfVtYOnU33o62mfQjy0C\r\n"
	        + "XyqsYB9FRDE5MBkGCSqGSIb3DQEJFDEMHgoAQQBsAGkAYwBlMBwGCSqGSIb3DQEJ\r\n"
	        + "FTEPBA0xMTczMzU5NDE3NTgwAAAAAAAAMIAGCSqGSIb3DQEHBqCAMIACAQAwgAYJ\r\n"
	        + "KoZIhvcNAQcBMBsGCiqGSIb3DQEMAQYwDQQIpgrMpONORjQCAQGggASCEZhvD90B\r\n"
	        + "aVlrz+0IZrNmu5xhDXMcVoaZrnASMo+Ieer2Z7s8l72rgGLknpcm4XsnzpEHg1gJ\r\n"
	        + "VQbiOVxQFsG7bEWdyiihrKgQdVBZIYQOC8Aejn/45vli0SxJJEbGS/QX1+TPDbMv\r\n"
	        + "zFGdAPRhiIA8+ssRNhlgCXkIKvO/Z6OCHw9s4yIknsxwzoHJwYOJOM1b89rZ7jRq\r\n"
	        + "qqVfVtAaSZILqgw3Td+e538G3pFltoBUL+WmewoVBraCHZZg1RKXP9FSDrHX9Dkj\r\n"
	        + "l6qDabEgFw8qg0gRy7mmtMnOph79UZ13plcOY8klqM7EFCSAB6zt2T2I4+BUmydf\r\n"
	        + "a70VjJH8nLcxPjww+2EEggQArXHulpRiNKwAA5UxqBbXwTmv9Bs5kDpXtYbBemWV\r\n"
	        + "HcUqiP8qZYddVgqYWMqn8Mj0i1OC17DLgEuHBRWQWKAOqEuKhrUv1dx4qyOdajr4\r\n"
	        + "IcHVkpYoRWaMAtrmsj+mmtF0JL3UfMJvJIq0zm20FLbvzOW0vE8ooLxiRXSDxxTr\r\n"
	        + "0jwBm2O45wp1bMTjGAd5Eka7G4ZpovTmBSp6RLySXzM0+9IN4HIc/dNLw3SEJurt\r\n"
	        + "sVvSorY8xaioGj8bkTa9ot41ljtXZRnfqu87Apmwfw9s/UPAMq+WTnX3iFxfE0W0\r\n"
	        + "tNtgXI7tY9J/Gp+b9SmwUxHcgRVHQ05BWaLA10pmcrtTUEn2LdGyrNHcr/a/+iCA\r\n"
	        + "QOcGvLnJrszP/AWBrbbMROadq9tmcHcoabScgpExeF0yEtdvgCNF97h4vgwzB2XA\r\n"
	        + "Y1d+8DCo4ZvxWRrwUWE1jiZubHHi1IYIAYm2guPdTwAupw45WtEzYwbwq21nycko\r\n"
	        + "MWUrcqI9Niz9AXCR4WWHi1nGwYYfEdz3QhveQQ/owTrE5F+MTrG3fmbIwaCx+oYM\r\n"
	        + "rID7jJRjfuIbsq/utC1zoEq1xcTC3G7RKd14v/NfyjHt3esonT/hkl+ZXAl/dSF2\r\n"
	        + "fg6bT09RAF6WZHGl9uPtILoVLYhjg9INYeOn2mdTGgqTmNiHTcwblMvHCskplIoZ\r\n"
	        + "OfpvqruGqvfysAWjzqghV+a0yCNTTw0JWr+8Ioovq16uYa7oofaQ8ieffvYDEswj\r\n"
	        + "X/WpIxyKSBc8BF0fzvtM3HkLyOS6vy7i33orrwm88P2FznedkW/XKcuSk/5H1927\r\n"
	        + "3rZ+t7Fq1dqpfmI+xj55Q4PSLOhEQLE2UCvF/nVucQU9VZ33KfPZRNoJOOkNxYlR\r\n"
	        + "enRC7tuZQDKWtjKKplOovUxzaHN9Kw2CV0O8G02FqLrBioGiJZgUO6TQRj9A944r\r\n"
	        + "g9OymCoI98Yvr//JMXwdEyX1V8NBc5VXUZae8ciMeIJkM1Zj3Kv8n6GqEMXCYog8\r\n"
	        + "zANn/7qXF+9+4n2efnSXka0IjxB+YUOqX9EPEtMlFeNzL/Fs2sIL+UdX86joUw+Z\r\n"
	        + "W0I1rU8/0517BQxJNy94x5nf9muMSMPV98utUuUQvZupOOLEwp2VsVtsxhpPwVVT\r\n"
	        + "qIt0i7aaQXqOkc1efEYvLTIIF9rWk+vsLXXeF8Nvc216veTVtkXpgI36U2jEgRd2\r\n"
	        + "jtZ9BAbI1yU3U6CIw5+ZemZoPtqIM+gUI5SrNI325muKcx4E5ezMCw+pM8nLxBiP\r\n"
	        + "WdQG7H6Mljf0KoXb8FVL/KzIYgC9/70qKm2iaB1M1O0TYnYjP0acQtrPG0NDUZaY\r\n"
	        + "beii4sk2ncqAfMdOnjGPcsxqH38DAnKSxbuCUs+abp/bbgSCBAB9L9l/DnNLhM/P\r\n"
	        + "bAKLe4IMzfrlSAXvmK4zMTyEeP23LZ+Tvfpe/CrT7VJ94c9Dj23zo9KBbd/vwgbI\r\n"
	        + "u8XUMIRJ3nNF9npMIryZoNPzL2/VE1YtQrTzbjlV3LnZukCeoh7KcvBRKxFHs8tH\r\n"
	        + "wEXyfchqYOG5xVLFn5j1AYTMHDvXs219qDkQbtUA1nvy/3SnG9yo/JpxVjptI4PW\r\n"
	        + "m5M269gvrPSfIgz666nUz0dk/8UbrdL2WENP4u8UJ0glGZ0D7jx9HBoypHfbqRQM\r\n"
	        + "4d3DFUstITx/fRDCO/EFuyFrTk5sZfzbG9mapcDVWnQiAqLQEwl1Zog1E8CVjQqQ\r\n"
	        + "o7DfWHbH7gmlF2AX6ZK9/p2u7Nz+h503v5HxRnMq1I+z/Dnc8a3YWK397OYdN2F/\r\n"
	        + "EtGJH9JdIDuBPsw0RYoWynUHH2AmWvk38sg9oUJGrd47pF2ZXUaVXvmXZBhiSetU\r\n"
	        + "MSJGsBVOyoBNvWFeIRigrdG8KmuaUnSpuyLmAygbm68wbt14ciHklhxA4c0Av4Zk\r\n"
	        + "IkvHM96mJkZS0KCmwDIPOyB6JV5mN0ACIgNOf8FI4DMEGG4EfeESlkvDj9nByt0Q\r\n"
	        + "XNwnATsQCrd+yksUnbijOpkMTxZtHKSO6wYKl8PlKvBcnq9OTClVCnTGHDfJUlnT\r\n"
	        + "ERJyt+hpJg3k7Wlu4pGAPDcqVmpSdKjaXxBSZcTV25mZsySBzOt52Pvf4PKg/BcY\r\n"
	        + "8sHYbLpy1ZX4ye52p1PB0hdzPWffr4Y6O6wsZoRMNYv45HYApTvbDR0cEV1ENb5b\r\n"
	        + "VShXoQ03DuCZYYwTrKQoV8Bt5pdrS/nNlIdVxQZ1TmUrq9h2cG3Tx2r6DGAeIGG5\r\n"
	        + "5igxjLissHsgZlN5x0RZfq388tkII0+9WjF3KdEzKcJWkTbmM9d97y8iSfqhPb5f\r\n"
	        + "6jEJHRpsrB2bFnmUIwqGXDZCz2r7PYLFRQG14AoweoHpbjFyCPKjX0wlgxSARycU\r\n"
	        + "YsU0ps0fiqEHLpdFokO27i7fgmWXhq0oqy1KHue1C+hzBqxKEXwxSRp3atGaWsGs\r\n"
	        + "qr0CxRSewvBDP8xU9mdI126FDB0KlbihG7i+e2dfCygmbKXcU1H/mjyNQCUeiPMA\r\n"
	        + "cfgQQnDC6oUWQW7ENoYtFKIh3fTe3zch/ZnidjDGx8+QSSI2mqjXs7ds/S0D/LyZ\r\n"
	        + "06Bj4PaGsEPf+nij3XOgvPtcf9LH+FT0aET0+x9HNYnxh/11F0cYdHKwZeRd+IwU\r\n"
	        + "Zah1K0QqJP1bNUass7bYDo4qTO9a01CBQM5Ducxqg7LOelWrTfdXBw+1FYtNRzwF\r\n"
	        + "L036xO2SvZxPQlldtXwKXDOqE8dYD7DSQswDAC5Xlf90bl1pWDQVsn7xQxZVGP/g\r\n"
	        + "1o5HcP3SBIIEAIDPQqTmqs5ua2a4+0KVdJSOd/nFl+SXtF/b2Qta4pnH44pHxTPI\r\n"
	        + "aZLwceV6xy68PHuEU1RkUpadugjsbb1z1yYIWBTwenY0AOA+KludQ0r80bnjZloj\r\n"
	        + "4gKhb5zValY50o6qAlGi6zWgjuvIHblTJuMX9acn4/+FYLkBXwTIKBnN/yFQ5xc9\r\n"
	        + "DI3nB+xtVT2yS3QpgviTHubGHZT8EmzU8Dal3kThXBVWT0iX0YQrbS4+RaPZd6V0\r\n"
	        + "BF/2mqrhfSsxULzK64qSUtdC6ACugDh2VOobI4oi56po+aExvmzDAORmkB28//xH\r\n"
	        + "gAajnF3WbMsM8IfPPrsp7IbSD6zv2bm9P/V65RusF5Z3hbnPqaZCE+r5I9LzUsg8\r\n"
	        + "oB+AqrqSAb1/x5sas1qPCL97qxZIC056Z9eIs/kYU7EOIrKmXNWRf62GYxXZFMxF\r\n"
	        + "MLwfjgiZCIiK5EsfmTHacdWnYa9qGEboJl7VQUHtVnDMeAL29KVAuaeHd3m8pXMx\r\n"
	        + "wjx2OxN3COMI3QW8AFDOyibRB9yKTWRNfIX/y0OoQ1hQVdj334701Cy+Kso+GGl1\r\n"
	        + "7ObCwSpJZjDoIbs7A+xbqfdq6GZ2NCmTj3MzCjVkXbfAgdsK1j/loa+iGZ8fMrJa\r\n"
	        + "bbcRgBJhOE9j9ToXKCx1pID/9Z2M7XMjS9ZtBSdtbEk9S406ERCC4YPdYrc/kOSl\r\n"
	        + "ldsof7vQ0d0wLv7HiYa0nWApic4S+1O22+pW8jhOb3fPoBQPb0xyuEXasddFk7V1\r\n"
	        + "3C6LacVKGJ6s463EUW7eIx4va1SSbF6lqFpsnkEibPiD2sEv8hguP6mFxWSMlfJD\r\n"
	        + "AChamQh50sajcSUX1rzX6mdwkMHvMF5LuGBNaRS3OM3CCdcJk5PD6L7UEVAlgPaG\r\n"
	        + "G6WBi3Sxqcy7tFHCXApIVxzA7W9KQzJP4q6ViMqNKqjp9S5Gv8WJmMLeC6scNL/V\r\n"
	        + "zMpti2En4uGUbCLkDbSyS+H/OPW32BHTBWd2uGej623ib0BTktF4h3aKlanxqpH0\r\n"
	        + "47/8QXVryQngxzil0/koJNgb0n2WvRctAQrZCcTpt1fevh5WoM9ZmhExT9r0AOVQ\r\n"
	        + "PfE94MszT8d8CQjUKBfeS5bf/hAn/TjhQW91YIex7T54CdKBPJGIBlTIFkuvOf8h\r\n"
	        + "8ncrTtgNSkwzvNJggACenviJaS9XZG7A90F/atqku1hMGoIWMs55Gz1Zr9WOmGVV\r\n"
	        + "3Yg8rqq/qU5ozmuwZkFdyVMO33JMLvhGvKQcnu/L9gIj6C5q+cOC0laBE2ixXAcr\r\n"
	        + "F+0CWtHSZ7177Jijljd72G8u2dHQ5yWGQVSb96RBp6p8TBcrc5A4o8AbEaVLQg6g\r\n"
	        + "29AoyG/C9Pm92c6xv5nPvBbIXPJX1vEbdacEggQAOmDtx4GXlj/yKqe4NbQBTGoJ\r\n"
	        + "YcBpE6M2T3MptH5pRQG0WQNUYX7FGmkbzQQ02aHKbLAQuo2s9OR2gA6v4hPLDIoA\r\n"
	        + "tGvVamML8zPUPtR7zU+jWaow/LoWx8gN5oU3sZpk6s+72eB/sit6Mx/znH70e6tx\r\n"
	        + "RD8HSlq1DrN0Ws1LhUHgsMa7YyzapURa1GipvWkoYPVVXuyjcGaVNraPYZ/tHnMe\r\n"
	        + "V+52QpZcmAlbUp2l40uf2Ge9vVjdSNXWV+PYENzfzF6y7t029Sqdfx7gsb877MaC\r\n"
	        + "o7SzI9x2rrwcTXManRDop2l82LHQ5JlqAu2N1fA62IHSt8F/OX69xq7GcbflUAyr\r\n"
	        + "xKni+3C3G2Fqy6EQT2YPBYBMEoEEUeg6Q3xYpzSKKHeLMvzJY6szlwexI1XQVywq\r\n"
	        + "562+PKuNeK3I39rQqTWcbZJ/2y9j+vJcK7oynw0klwLxaa3cJkX4bxqb8N8DoXTV\r\n"
	        + "C0VdjcDJlWHdKyhYMxOQhfEPocXzpnYKVCTx/lGJ5GwgqUwwfzlev94qSaUS1OtV\r\n"
	        + "wCS9CjSQOrqjwPpONoYZ1SoPDI5FXnQLQNsVsuLm0FwAHSxhhy0oQnFfXaXaW1qT\r\n"
	        + "I9t4/MXBSEV/WlV0Jis33JlezhPuIgDhxPRNn9YFeHpMa/LSTKeFGS4KEsg5WoXr\r\n"
	        + "NHLObvO8Qe/QBMmjFhn1gDnYzJYTycgDrPjWPHw6+KMBPyPyrKlkkJwwRRH1aM0a\r\n"
	        + "hgBW9BtnJoX5An3I2c8Ag+uX1mOyiX53sS64VHEvdNfwkwfjOrx/DoRhvio+R1ur\r\n"
	        + "Uz86VYn0uFOtcFsF8fV+f4hjO9Ki306uKhhaPexot08Vz+QH+A49hw4HLF6ZkAgA\r\n"
	        + "LInLQDOyxvhDqdb1LOhrTeO0jM3nUDz3WQtcz8OMlN01iYANgjiqPVTVeQeidK9C\r\n"
	        + "5YWTYpQlmH0Z3+zM7XjZWnbomtKxQxnwNoeBnIjetKVjruX3Z54We3/KTsQIMc19\r\n"
	        + "0tDFziVL5k7NudTX90ns7sVPxTxM+2oQ99w6sAQ+/tPuB7fbEi0Z/lNo+OuuFByg\r\n"
	        + "OwoaNQjlmgMeVgbw1ORkO1QhvuaNEd83VgAHHeBDpi+D1K/3qACvyPnMvnXdmcGt\r\n"
	        + "/Ci6kfclJcjALr9yRqeajeUHLatFA/Xu2doBANwM3Kf8ZzTJpPzRM4EFc5w6fP6n\r\n"
	        + "F6hGNOK2CuxczaeBx5fM9m1heIX43TKvasK67wz+I3vOg/+mlpVVFEPyaSK6EeqV\r\n"
	        + "wnjZaaxMkehhiyHBjGlA5F2N2o/oHXPPYwcaGTsaOJUAkmcbahjyt8XijFD8EDG6\r\n"
	        + "MIt6HUjl6m+XNxlMACE+LRzjDFXyZLwtCBCkMeSlnIcrdPGBufxIIT2ocnzrgwSB\r\n"
	        + "ojJYqVgHf+SILvcRBC494qDM6D6+DudecweTk86sV6YP5QW41CY5HCgADY71N5M/\r\n"
	        + "/E5dGHQpi81hi7XEjrUQ5ZRbXYFQlGCZsELhwXP3IgQITza+Yt/mIscji2OawMy0\r\n"
	        + "s0lHFtQJejM9CVzePpcLzRsQpNZpPEwBZC5BwnBGhVcA/uaeWkmz3okKnm2sB9Sf\r\n"
	        + "6obMjf3JhQAAAAAAAAAAAAAAAAAAAAAAADAtMCEwCQYFKw4DAhoFAAQUvzkbxwk+\r\n"
	        + "wXGPUmmGMIBpTO+zd1sECHMpTXBuqvIqAAA=");

}
