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

package demo.md;

import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import demo.IAIKDemo;

/**
 * MessageDigest engine demo for some digest algorithms.
 * 
 * @version File Revision <!-- $$Revision: --> 25 <!-- $ --> 
 */
public class MD implements IAIKDemo {

  /**
   * The data to be digested.
   */
	private final static byte[] messageData = "message digest".getBytes();

	/**
	 * Pre-calculated digest value for MD5. 
	 */
	private final static byte[] messageDigestMd5 = Util.toByteArray("F9:6B:69:7D:7C:B7:93:8D:52:5A:2F:31:AA:F1:61:D0");
	/**
   * Pre-calculated digest value for SHA-1. 
   */
	private final static byte[] messageDigestSHA1 = Util.toByteArray("C1:22:52:CE:DA:8B:E8:99:4D:5F:A0:29:0A:47:23:1C:1D:16:AA:E3");
	/**
   * Pre-calculated digest value for SHA-224. 
   */
	private final static byte[] messageDigestSHA224 = Util.toByteArray("2C:B2:1C:83:AE:2F:00:4D:E7:E8:1C:3C:70:19:CB:CB:65:B7:1A:B6:56:B2:2D:6D:0C:39:B8:EB");
	 /**
   * Pre-calculated digest value for SHA-256. 
   */
	private final static byte[] messageDigestSHA256 = Util.toByteArray("F7:84:6F:55:CF:23:E1:4E:EB:EA:B5:B4:E1:55:0C:AD:5B:50:9E:33:48:FB:C4:EF:A3:A1:41:3D:39:3C:B6:50");
	/**
   * Pre-calculated digest value for SHA-384. 
   */
	private final static byte[] messageDigestSHA384 = Util.toByteArray("47:3E:D3:51:67:EC:1F:5D:8E:55:03:68:A3:DB:39:BE:54:63:9F:82:88:68:E9:45:4C:23:9F:C8:B5:2E:3C:61:DB:D0:D8:B4:DE:13:90:C2:56:DC:BB:5D:5F:D9:9C:D5");
  /**
   * Pre-calculated digest value for SHA-512. 
   */	
	private final static byte[] messageDigestSHA512 = Util.toByteArray("10:7D:BF:38:9D:9E:9F:71:A3:A9:5F:6C:05:5B:92:51:BC:52:68:C2:BE:16:D6:C1:34:92:EA:45:B0:19:9F:33:09:E1:64:55:AB:1E:96:11:8E:8A:90:5D:55:97:B7:20:38:DD:B3:72:A8:98:26:04:6D:E6:66:87:BB:42:0E:7C");
  /**
   * Pre-calculated digest value for SHA512/224. 
   */ 
	private final static byte[] messageDigestSHA512_224 = Util.toByteArray("AD:1A:4D:B1:88:FE:57:06:4F:4F:24:60:9D:2A:83:CD:0A:FB:9B:39:8E:B2:FC:AE:AA:E2:C5:64");
  /**
   * Pre-calculated digest value for SHA512/256. 
   */ 
	private final static byte[] messageDigestSHA512_256 = Util.toByteArray("0C:F4:71:FD:17:ED:69:D9:90:DA:F3:43:3C:89:B1:6D:63:DE:C1:BB:9C:B4:2A:60:94:60:4E:E5:D7:B4:E9:FB");
  /**
   * Pre-calculated digest value for SHA3-224. 
   */ 
	private final static byte[] messageDigestSHA3_224 = Util.toByteArray("18:76:8B:B4:C4:8E:B7:FC:88:E5:DD:B1:7E:FC:F2:96:4A:BD:77:98:A3:9D:86:A4:B4:A1:E4:C8");
  /**
   * Pre-calculated digest value for SHA3-256. 
   */ 
	private final static byte[] messageDigestSHA3_256 = Util.toByteArray("ED:CD:B2:06:93:66:E7:52:43:86:0C:18:C3:A1:14:65:EC:A3:4B:CE:61:43:D3:0C:86:65:CE:FC:FD:32:BF:FD");
  /**
   * Pre-calculated digest value for SHA3-384. 
   */ 
	private final static byte[] messageDigestSHA3_384 = Util.toByteArray("D9:51:97:09:F4:4A:F7:3E:2C:8E:29:11:09:A9:79:DE:3D:61:DC:02:BF:69:DE:F7:FB:FF:DF:FF:E6:62:75:15:13:F1:9A:D5:7E:17:D4:B9:3B:A1:E4:84:FC:19:80:D5");
  /**
   * Pre-calculated digest value for SHA3-512. 
   */ 
	private final static byte[] messageDigestSHA3_512 = Util.toByteArray("34:44:E1:55:88:1F:A1:55:11:F5:77:26:C7:D7:CF:E8:03:02:A7:43:30:67:B2:9D:59:A7:14:15:CA:9D:D1:41:AC:89:2D:31:0B:C4:D7:81:28:C9:8F:DA:83:9D:18:D7:F0:55:6F:2F:E7:AC:B3:C0:CD:A4:BF:F3:A2:5F:5F:59");
  /**
   * Pre-calculated digest value for RIPEMD128. 
   */ 
	private final static byte[] messageDigestRIPEMD128 = Util.toByteArray("9E:32:7B:3D:6E:52:30:62:AF:C1:13:2D:7D:F9:D1:B8");
  /**
   * Pre-calculated digest value for RIPEMD160. 
   */ 
	private final static byte[] messageDigestRIPEMD160 = Util.toByteArray("5D:06:89:EF:49:D2:FA:E5:72:B8:81:B1:23:A8:5F:FA:21:59:5F:36");
  /**
   * Pre-calculated digest value for RIPEMD256. 
   */ 
	private final static byte[] messageDigestRIPEMD256 = Util.toByteArray("87:E9:71:75:9A:1C:E4:7A:51:4D:5C:91:4C:39:2C:90:18:C7:C4:6B:C1:44:65:55:4A:FC:DF:54:A5:07:0C:0E");
  /**
   * Pre-calculated digest value for RIPEMD320. 
   */ 
	private final static byte[] messageDigestRIPEMD320 = Util.toByteArray("3A:8E:28:50:2E:D4:5D:42:2F:68:84:4F:9D:D3:16:E7:B9:85:33:FA:3F:2A:91:D2:9F:84:D4:25:C8:8D:6B:4E:FF:72:7D:F6:6A:7C:01:97");
  /**
   * Pre-calculated digest value for WHIRLPOOL. 
   */ 
	private final static byte[] messageDigestWHIRLPOOL = Util.toByteArray("37:8C:84:A4:12:6E:2D:C6:E5:6D:CC:74:58:37:7A:AC:83:8D:00:03:22:30:F5:3C:E1:F5:70:0C:0F:FB:4D:3B:84:21:55:76:59:EF:55:C1:06:B4:B5:2A:C5:A4:AA:A6:92:ED:92:00:52:83:8F:33:62:E8:6D:BD:37:A8:90:3E");

	
	/**
	 * Calculated a digest over the given message data using the given digest algorithm and compares
	 * the resulting digest value with the expected result.
	 * 
	 * @param algName the name of the digest algorithm to be used
	 * @param expectedResult the expected digest value
	 * 
	 * @return <code>true</code> if the result is correct, <code>false</code> if it is not correct
	 * 
	 * @throws NoSuchAlgorithmException if no MessageDigest engine for the requested algorithm is available
	 * @throws NoSuchProviderException if the IAIK provider is not installed
	 */
	private static boolean calculateDigest(String algName, byte[] messageData, byte[] expectedResult) 
	  throws NoSuchAlgorithmException, NoSuchProviderException {
	  
	  MessageDigest md = MessageDigest.getInstance(algName, "IAIK");
	  byte[] result = md.digest(messageData);
	  boolean ok = CryptoUtils.secureEqualsBlock(result, expectedResult);
	  if (ok) {
      System.out.println("Message digest using " + algName + " correct.");
    } else {
      System.out.println("Message digest using " + algName + " NOT correct:");
      System.out.println("out:    " + Util.toString(result));
      System.out.println("should: " + Util.toString(expectedResult));
    }
	  
	  System.out.println("private final static byte[] messageDigest"+algName+" = Util.toByteArray(\""+Util.toString(result)+"\");");
	  return ok;
	}

  /**
   * Starts the demo.
   */
	public void start() {
		try {
			boolean ok = true;

			ok &= calculateDigest("MD5", messageData, messageDigestMd5);
			ok &= calculateDigest("SHA-1", messageData, messageDigestSHA1);
			ok &= calculateDigest("SHA-224", messageData, messageDigestSHA224);
			ok &= calculateDigest("SHA-256", messageData, messageDigestSHA256);
			ok &= calculateDigest("SHA-384", messageData, messageDigestSHA384);
			ok &= calculateDigest("SHA-512", messageData, messageDigestSHA512);
			ok &= calculateDigest("SHA512/224", messageData, messageDigestSHA512_224);
			ok &= calculateDigest("SHA512/256", messageData, messageDigestSHA512_256);
			ok &= calculateDigest("SHA3-224", messageData, messageDigestSHA3_224);
			ok &= calculateDigest("SHA3-256", messageData, messageDigestSHA3_256);
			ok &= calculateDigest("SHA3-384", messageData, messageDigestSHA3_384);
			ok &= calculateDigest("SHA3-512", messageData, messageDigestSHA3_512);
			ok &= calculateDigest("RIPEMD128", messageData, messageDigestRIPEMD128);
			ok &= calculateDigest("RIPEMD160", messageData, messageDigestRIPEMD160);
			ok &= calculateDigest("RIPEMD256", messageData, messageDigestRIPEMD256);
			ok &= calculateDigest("RIPEMD320", messageData, messageDigestRIPEMD320);
			ok &= calculateDigest("WHIRLPOOL", messageData, messageDigestWHIRLPOOL);

			if (ok) System.out.println("MD demo OK! No ERRORS found!\n");
			else throw new RuntimeException("MD demo NOT OK! There were ERRORS!!!");
		} catch (Exception ex) {
			ex.printStackTrace();
			throw new RuntimeException();
		}
	}

	/**
	 * Performs some tests for MD.
	 */
	public static void main(String arg[]) {

		Security.insertProviderAt(new IAIK(), 2);

		(new MD()).start();
		iaik.utils.Util.waitKey();
	}
}
