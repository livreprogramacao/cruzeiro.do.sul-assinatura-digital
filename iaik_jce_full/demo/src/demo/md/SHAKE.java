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

import iaik.security.md.SHAKE128InputStream;
import iaik.security.md.SHAKE256InputStream;
import iaik.security.md.SHAKEInputStream;
import iaik.security.provider.IAIK;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.IOException;
import java.security.Security;

import demo.IAIKDemo;

/**
 * SHAKEInputStream demo for the SHA-2 Extendable Output Functions (XOFs) SHAKE128 and SHAKE256.
 * <p>
 * With SHAKE128 and SHAKE256 NIST (FIPS PUB 202) specifies two Extendable Output Functions (XOFs)
 * in addition to the SHA-3 hash functions. In contrast to a hash function a XOF can produce output
 * of arbitrary length.
 * <p>
 * SHAKE is a based on a so-called <i>sponge</i> function. Using it consists of two phases: during 
 * the <i>update</i> phase input data is absorbed by the XOF and during the <i>read</i> phase output
 * data is squeezed from the XOF.
 * <br>
 * This demo shows how to update a SHAKEInputStream with input date and subsequently reading output
 * data from it. Since an XOF can produce output data of arbitrary length using the SHAKEInputStream
 * <code>read</code> methods has to be done carefully to not run into an indefinite loop. This demo
 * shows two variants of controlling the output data length. {@link #calculateOutput(String, byte[], byte[]) First}
 * the desired data output length is controlled outside the stream, and {@link #calculateOutput(String, byte[], int, byte[]) 
 * second} the maximum allowed data output size is announced when creating the SHAKEInputStream so that
 * the stream can check for EOF during producing output data. 
 * <p>
 * Although it is possible to use an XOF as a hash function for a fixed output length,
 * XOFs have the potential for generating related outputs. When selecting two different
 * output length values for a common message, the two outputs of the XOF will be closely
 * related. The longer output will be an extension of the shorter output. For that reason
 * XOFs should be used with special care. See (the Security section of) NIST FIPS PUB 202
 * for more information! Please be aware that SHAKE128 is approved as XOF, but NOT as hash 
 * function. Approved XOF use cases may be specified in further NIST Special Publications.
 */
public class SHAKE implements IAIKDemo {

  /**
   * The data to be absorbed.
   */
	private final static byte[] messageData = "This is the input data!".getBytes();
	
	/**
	 * Output size.
	 */
	private final static int outputSize = 512;

	/**
	 * Pre-calculated 512 byte XOF output for SHAKE128. 
	 */
	private final static byte[] resultSHAKE128 = Util.toByteArray(
	  "54:16:72:1E:98:B8:0F:49:66:D5:72:B2:56:AC:54:49:5F:42:E7:62:8E:F2:99:0C:08:9F:D7:74:97:C9:BB:EB:3F:B2:39:43:"+
    "35:FF:5C:32:57:A1:20:21:DF:EC:8F:E5:6A:1D:78:E4:E9:C7:2C:65:E1:B6:45:75:0B:9D:1D:76:32:98:9B:CC:FA:9D:83:DB:"+
    "60:51:C5:AF:1E:C3:F0:28:01:6C:EE:F6:7E:5C:C5:81:45:76:AC:3B:ED:D2:E1:B4:FE:B2:7B:EF:07:82:F6:A9:21:44:A2:53:"+
    "A6:56:CB:8A:28:BC:55:F0:2A:B3:2E:AF:D1:F6:94:38:36:C8:57:F2:DA:0A:32:D3:96:7C:5A:91:38:95:C7:74:B8:86:CB:BE:"+
    "C6:E5:C5:5E:D6:C3:17:F1:66:AC:DB:F9:33:F9:9E:D1:E6:05:6B:32:F7:3B:96:63:88:3F:0A:C1:45:3B:E9:12:DA:1C:AD:48:"+
    "DB:4E:82:39:63:84:9E:94:91:35:04:83:93:46:CD:96:EB:60:D5:98:5F:0E:95:E9:1C:C6:89:FC:C4:13:40:6D:2A:5B:AF:76:"+
    "65:75:6C:40:ED:37:C8:1B:39:5E:CB:7D:19:82:E5:A9:28:F0:2F:5A:3C:AF:FB:E2:C3:67:F8:EA:10:1A:7D:B9:9F:CD:DA:F9:"+
    "C5:24:58:77:35:59:1D:63:8A:CA:84:AF:F7:3A:CA:9D:F8:3E:07:9F:6E:0D:A6:CC:EF:BF:38:E8:D8:DA:29:13:7F:8C:BA:10:"+
    "9E:DE:46:E8:9A:18:CA:C2:B8:46:10:EE:CF:60:08:CD:E3:FE:2E:0F:D3:B1:A6:EE:8A:03:B1:E6:97:23:A6:FE:06:44:5F:2C:"+
    "F8:80:80:1D:F1:37:32:80:8A:C1:7A:2C:E0:FE:5A:8B:A0:70:17:6F:2A:00:72:48:4F:39:82:16:B5:8B:30:BA:AF:E8:17:E2:"+
    "7E:7D:01:01:7D:1C:D6:99:8D:9E:9B:F4:E5:A9:5A:A1:5F:9B:F8:0F:A6:A6:E0:4A:00:DA:C2:B5:8D:8B:1A:70:CA:C7:CE:E0:"+
    "E7:5E:C0:E4:95:66:B4:E1:AC:1B:07:AC:4E:6B:56:CC:EE:CD:C6:9A:C6:8A:DF:ED:9E:8E:7E:63:26:3A:3C:93:BA:1C:2D:2A:"+
    "EF:E6:F8:3E:84:AE:B3:CE:FB:BB:EC:B3:2E:87:74:06:77:9D:06:27:A2:EF:1F:E6:51:B1:B7:DF:20:C0:71:19:C7:5F:8A:FD:"+
    "C4:C6:15:BF:DB:B6:68:4B:A4:6A:09:1C:37:49:F9:69:B0:F3:30:E6:F6:88:EF:24:49:A7:E0:E9:31:1F:83:42:41:2A:CF:F2:"+
    "E9:F0:8B:84:E4:97:A2:17");
	
	/**
   * Pre-calculated 512 byte XOF output for SHAKE256. 
   */
	private final static byte[] resultSHAKE256 = Util.toByteArray(
	  "CE:02:C6:80:7D:EE:A7:E9:64:05:F7:0D:4B:FA:E1:9C:0A:A9:ED:53:4D:BE:A9:F0:E4:BB:2F:F0:9F:1F:75:25:9E:5D:83:55:"+
    "2D:6F:76:0D:E2:C9:44:8A:F8:28:64:73:FD:8A:34:E6:63:84:48:C6:FD:BB:4D:99:44:2E:F0:F5:1F:7F:9F:05:0C:9C:84:75:"+
    "85:2A:D8:7D:74:F8:55:50:F8:D9:4D:02:8B:28:4E:1D:B6:48:7A:7E:75:D5:23:3C:4B:F6:10:7F:27:F9:7C:93:D4:68:06:E4:"+
    "46:14:D2:23:3C:B3:EF:6F:D0:36:5A:E5:F1:21:B6:58:E9:E8:13:DD:F0:AA:8B:BE:B5:74:FC:34:B6:9A:B5:D3:24:5F:92:6E:"+
    "2D:CE:9C:E9:59:32:CF:EC:3E:FE:58:C3:9A:EF:0E:95:16:26:B4:BF:F1:B2:47:C6:BB:4A:7A:70:1D:13:BF:72:4E:61:09:BC:"+
    "A9:7D:C0:F4:6B:B0:27:88:09:BF:6C:B9:94:6A:BC:93:12:C0:1E:74:50:21:6C:F4:70:DA:88:77:38:94:60:2A:9B:69:C3:AA:"+
    "D0:42:3C:9D:4B:49:5B:4C:3C:A5:23:34:39:FF:07:AA:B5:67:3B:97:D6:90:51:AE:36:70:23:BF:54:5F:42:38:A5:77:0A:44:"+
    "52:04:A4:F9:FD:F4:B4:B5:F9:1B:EC:CA:FD:49:21:8C:9E:60:7C:91:6F:99:9F:8E:8E:6B:6B:A2:CD:6A:A6:89:ED:AF:C9:47:"+
    "6C:B6:4C:29:7F:7A:37:5A:B4:D3:44:20:84:C1:4A:2C:5A:EE:14:E9:D5:BB:8A:3B:33:43:7E:38:D0:F9:AF:6F:3E:6B:91:DE:"+
    "C4:40:0B:0C:9A:59:EB:9C:41:DE:69:88:47:6A:E5:3A:AB:5F:0F:92:D0:E2:D9:DE:86:98:EA:2A:43:41:F0:6C:43:07:DE:C9:"+
    "02:BF:2A:76:E4:A1:CA:2B:09:6E:7D:6A:11:28:05:F9:53:F5:AD:35:8F:2D:AA:2F:9E:9A:DB:55:AE:18:77:8E:FB:76:74:1A:"+
    "B9:0A:59:41:A4:98:2B:5B:70:90:13:2B:1E:36:42:4C:49:D6:B8:92:37:75:0B:34:2B:F0:08:CF:A1:71:6F:73:2F:13:E1:A5:"+
    "2C:EC:EB:35:1B:AE:01:EA:39:2B:83:F3:97:20:75:92:2F:F5:F3:02:31:30:B7:F3:73:1F:E0:D7:08:F8:D1:8A:41:1A:83:F4:"+
    "BD:F2:F0:FE:29:85:9C:3C:FD:99:54:AA:00:C7:DB:02:40:E2:89:45:70:C9:30:5C:80:A3:19:2F:83:36:BA:AC:DC:38:8B:B0:"+
    "A2:F2:BB:F8:6B:D9:1B:3B");
	
	/**
	 * Calculates XOF output over the given message data using the given XOF algorithm and compares
	 * the resulting value with the expected result.
	 * This method controls the data output size outside the stream.
	 * 
	 * @param algName the name of the XOF algorithm to be used
	 * @param expectedResult the expected output value
	 * 
	 * @return <code>true</code> if the result is correct, <code>false</code> if it is not correct
	 * 
	 * @throws NoSuchAlgorithmException if no implementation for the requested algorithm is available
	 * @throws NoSuchProviderException if the IAIK provider is not installed
	 */
	private static boolean calculateOutput(String algName, byte[] messageData, byte[] expectedResult) 
	  throws IOException {
	  
	  SHAKEInputStream shakeInputStream; 
	  if (algName.equals("SHAKE128")) {
	    shakeInputStream = new SHAKE128InputStream();
	  } else {
	    shakeInputStream = new SHAKE256InputStream() ;
	  }  
	 
	  // update with input data
	  shakeInputStream.update(messageData);
	  
	  // read output data
	  byte[] result = new byte[outputSize];
	  shakeInputStream.read(result);
	  
	  boolean ok = CryptoUtils.secureEqualsBlock(result, expectedResult);
	  if (ok) {
      System.out.println("XOF output using " + algName + " correct.");
    } else {
      System.out.println("XOF output using " + algName + " NOT correct:");
      System.out.println("out:    " + Util.toString(result));
      System.out.println("should: " + Util.toString(expectedResult));
    }
	  return ok;
	}
	
	/**
   * Calculates XOF output over the given message data using the given XOF algorithm and compares
   * the resulting value with the expected result.
   * This method tells the SHAKEInputStream the maximum data to be may be read. 
   * 
   * @param algName the name of the XOF algorithm to be used
   * @param maxReadSize the maximum number of byte to may be read from the stream 
   * @param expectedResult the expected output value
   * 
   * @return <code>true</code> if the result is correct, <code>false</code> if it is not correct
   * 
   * @throws NoSuchAlgorithmException if no MessageDigest engine for the requested algorithm is available
   * @throws NoSuchProviderException if the IAIK provider is not installed
   */
  private static boolean calculateOutput(String algName, 
      byte[] messageData, int maxReadSize, byte[] expectedResult) 
    throws IOException {
    
    SHAKEInputStream shakeInputStream; 
    if (algName.equals("SHAKE128")) {
      shakeInputStream = new SHAKE128InputStream(maxReadSize);
    } else {
      shakeInputStream = new SHAKE256InputStream(maxReadSize) ;
    }  
   
    // update with input data
    shakeInputStream.update(messageData);
    
    // read output data
    byte[] result = new byte[outputSize];
    // small buffer just for demonstration purposes
    byte[] buf = new byte[128];
    int r = -1;
    int off = 0;
    while ((r = shakeInputStream.read(buf)) != -1) {
      System.arraycopy(buf, 0, result, off, r);
      off+=r;
    }
    
    boolean ok = CryptoUtils.secureEqualsBlock(result, expectedResult);
    if (ok) {
      System.out.println("XOF output using " + algName + " correct.");
    } else {
      System.out.println("XOF output using " + algName + " NOT correct:");
      System.out.println("out:    " + Util.toString(result));
      System.out.println("should: " + Util.toString(expectedResult));
    }
    
    return ok;
  }

  /**
   * Starts the demo.
   */
	public void start() {
		try {
			boolean ok = true;

			ok &= calculateOutput("SHAKE128", messageData, resultSHAKE128);
			ok &= calculateOutput("SHAKE256", messageData, resultSHAKE256);
			
			ok &= calculateOutput("SHAKE128", messageData, outputSize, resultSHAKE128);
      ok &= calculateOutput("SHAKE256", messageData, outputSize, resultSHAKE256);

			if (ok) System.out.println("SHAKE XOF demo OK! No ERRORS found!\n");
			else throw new RuntimeException("SHAKE XOF demo NOT OK! There were ERRORS!!!");
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

		(new SHAKE()).start();
		iaik.utils.Util.waitKey();
	}
}
