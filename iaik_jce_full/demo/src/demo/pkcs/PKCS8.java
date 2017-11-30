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

import iaik.pkcs.pkcs8.EncryptedPrivateKeyInfo;
import iaik.security.provider.IAIK;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;

import demo.IAIKDemo;
import demo.keystore.IaikKeyStore;

/**
 * This class demonstrates the usage of the PKCS#8 EncryptedPrivateKeyInfo
 * implementation to password based protect private keys.
 * .
 * @version File Revision <!-- $$Revision: --> 11 <!-- $ -->
 */
public class PKCS8 implements IAIKDemo {

	/**
	 * Shows how to encrypt/decrpyt private keys.
	 */
	public void start() {

		try {
		  // the private key to be protected
			PrivateKey privateKey = IaikKeyStore.getPrivateKey(IaikKeyStore.RSA,
			    IaikKeyStore.SZ_1024);
			// the test password
			char[] password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
			
			boolean ok = true;
			
			// the PBE algorithms to be used
			String[] algorithms = {
			  
			  // PBES1, PKCS#5  
  	    "PbeWithMD5AndDES_CBC",

  	    // PBES1, PKCS#12
	      "PbeWithSHAAnd3_KeyTripleDES_CBC",
	      "PbeWithSHAAnd40BitRC2_CBC",

	      // PBES2, PKCS#5
	      "PBES2WithHmacSHA1AndDESede",
	      "PBES2WithHmacSHA1AndAES",
	      "PBES2WithHmacSHA256AndAES",
	      "PBES2WithHmacSHA384AndAES192",
	      "PBES2WithHmacSHA512AndAES256",
			};
			
			System.out.println("EncryptedPrivateKeyInfo demo using... ");
			for (int i = 0; i < algorithms.length; i++) {
			  String algorithm = algorithms[i];
			  System.out.println("  ..." + algorithm);
			  ok &= encryptDecrypt(privateKey, algorithm, password);
			}
			
      if (ok) { 
        System.out.println("EncryptedPrivateKeyInfo demo OK! No ERRORS found!\n");
      } else {
        throw new RuntimeException("EncryptedPrivateKeyInfo demo NOT OK! There were ERRORS!!!");
      }

		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}
	
	/**
	 * Wraps the given private key into an EncryptedContentInfo, encrypts it,
	 * and decrypts and unwraps it again.
	 * 
	 * @param privateKey the PrivateKey to be protected
	 * @param algorithm the PBE algorithm to be used
	 * @param password the password to be used
	 * 
	 * @return <code>true</code> if en/decryption gives the right private key
	 * 
	 * @exception GeneralSecurityException if en/decryption fails for some reason
	 * 
	 */
	private boolean encryptDecrypt(PrivateKey privateKey, String algorithm, char[] password) throws GeneralSecurityException {

	  // wrap, encrypt, encode
	  EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(
        privateKey);
    epki.encrypt(password, algorithm);
    byte[] encodedEpki = epki.getEncoded(); 
    
    // decode, decrypt, unwrap
    epki = new EncryptedPrivateKeyInfo(encodedEpki);
    
    PrivateKey decryptedPrivateKey = epki.decrypt(password);
    
    return (privateKey.equals(decryptedPrivateKey));
	  
	}

	/**
	 * Main method.
	 *
	 * @exception IOException if an I/O Error occurs
	 */
	public static void main(String arg[])
	    throws IOException
	{

		Security.insertProviderAt(new IAIK(), 2);

		(new PKCS8()).start();
		System.in.read();
	}
}
