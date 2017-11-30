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

package demo;

import iaik.security.rsa.RSAPrivateKey;
import iaik.security.rsa.RSAPublicKey;
import iaik.utils.Util;

import java.security.Key;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class measures the execution speed of the IAIK-JCE cryptographic
 * implementations for typical applications. This class can also be used to
 * benchmark other JCA/JCE compatible providers, like the default Sun provider
 * for MD5 and SHA-1 hashes or the SunJCE provider. You should notice that the
 * IAIK provider is significantly faster on most algorithms.
 * <P>
 * Note: This class has been adapted to work both with and without a preemptive
 * thread scheduler. The functionality and results are the same, however, when
 * run on a non preemptive scheduler the setup time for each test will be
 * approximately 0.5 seconds longer. Again, this has marginal effects on the
 * test results at most.
 * <P>
 * Note: When using HotSpot or similar virtual machines the test results may not
 * be completely accurate, in particular the result for the smallest block size
 * may be too low; also the scheduler type detection may be incorrect. This will
 * not happen on ordinary JIT compilers.
 * <p>
 * The test goes over several block sizes:
 * <p>
 * md2, md5, sha, sha1, sha224, sha256, sha384, sha512, ripemd128, ripemd160,
 * ripemd256, ripemd320, whirlpool, arcfour, des cbc, des ede3 cbc, idea cbc,
 * rc2 cbc, blowfish cbc, rc5 cbc, gost cbc, cast128 cbc, rc6 cbc, mars cbc,
 * twofish cbc, aes cbc, serpent cbc, rijndael256 cbc, camellia cbc for 8, 64,
 * 256, 1024 and 8192 bytes; rsa for 512, 1024 and 2048 bits.
 * <p>
 * The results are printed in 1000s of bytes per second processed.
 * <P>
 * Usage: java demo.TestSpeed [p=name.of.provider.class] [t=time]
 * [hashes|ciphers|rsa|all]
 * <P>
 * <UL>
 * <LI>Use p= to specify the provider to test. Default is IAIK JCE (
 * <CODE>iaik.security.provider.IAIK</CODE>) but you can also benchmark
 * <CODE>sun.security.provider.Sun</CODE>,
 * <CODE>com.sun.crypto.provider.SunJCE</CODE> or any other 1.2 compatible
 * provider.
 * <LI>Use t= to specify for how long each speed test is done in seconds.
 * Default is 3.0 seconds, you can also specify e.g. "1.5"
 * <LI>Select which tests are to be conducted: "hashes" will do message digests
 * only, "ciphers" will do only the ciphers, "ccmgcm" will do CCM, GCM ciphers,
 * and "rsa" only the RSA algorithm. "all" will do all of them, it is the
 * default. Any algorithm not implemented by a particular provider will just be
 * skipped.
 * </UL>
 * <P>
 * The results below were obtained on an Intel(R) Core(TM) i5 661 3.33 GHz, 4.0
 * GB RAM running Windows 7 Enterprise (64 bit) as well as Ubuntu Linux 10.10
 * (x64) network connected with standard services active. The tests were done on
 * IAIK JCE 4.0 release with JDK 1.6.0, each test for 3.0 seconds.
 * 
 * <PRE>
 *     Security provider: IAIK, version 4.0
 *     Java VM: Sun Microsystems Inc., version 1.6.0_21, JIT (none)
 *     OS: Windows 7/amd64, version 6.1
 *     
 *     The 'numbers' are in 1000s of bytes per second processed.
 *     type              8 bytes   64 bytes   256 bytes   1024 bytes   8192 bytes
 *     md2              12194.4k    12414.5k    12520.0k    12515.5k    12496.1k
 *     md5             188328.7k   285878.4k   295899.7k   297247.0k   300034.0k
 *     sha1            129383.7k   175427.5k   177059.7k   175299.8k   177296.5k
 *     sha224           94141.8k   114280.9k   115982.7k   112818.1k   118113.3k
 *     sha256           96001.7k   115259.1k   116368.5k   117457.8k   118105.1k
 *     sha384          127781.2k   168169.8k   171926.2k   172406.0k   172127.2k
 *     sha512          135050.0k   169524.2k   173123.7k   172842.0k   173615.4k
 *     ripe md128      139295.9k   196812.6k   198158.1k   200562.5k   200776.0k
 *     ripe md160       90381.4k   107939.4k   108351.0k   108723.5k   108838.5k
 *     ripe md256      135339.2k   185902.7k   186569.7k   187682.4k   186935.9k
 *     ripe md320       86904.9k   104594.4k   104610.7k   104804.7k   104915.2k
 *     whirlpool        23823.8k    40698.0k    40764.7k    40883.4k    40968.1k
 *     arcfour         113952.8k   166510.0k   174203.6k   176120.5k   176767.5k
 *     des cbc          47180.8k    53310.2k    53977.4k    53800.6k    54209.7k
 *     des ede3 cbc     20726.6k    21891.0k    22003.7k    21991.3k    22015.8k
 *     idea cbc         37702.0k    41406.5k    42043.9k    41961.8k    42246.8k
 *     rc2 cbc          36280.8k    39061.7k    39471.0k    39189.5k    39417.3k
 *     blowfish cbc     56223.1k    63766.1k    64689.9k    64960.7k    65146.8k
 *     rc5 cbc          82316.6k   101102.7k   103879.2k   105049.9k   104890.7k
 *     gost cbc         40901.7k    45502.1k    45594.5k    45990.5k    46061.2k
 *     cast128 cbc      62646.8k    72327.8k    73154.0k    73308.6k    73673.5k
 *     rc6 cbc              n/a    104677.0k   107458.9k   108517.1k   108716.0k
 *     mars cbc             n/a     91729.8k    94381.6k    95096.3k    95172.4k
 *     twofish cbc          n/a     93787.8k    96551.5k    96627.0k    96777.6k
 *     aes cbc              n/a     83938.1k    86525.9k    86922.6k    86985.9k
 *     serpent cbc          n/a     50651.3k    55875.7k    56031.6k    56315.5k
 *     rijndael-256 cbc     n/a     59858.1k    62351.5k    62812.9k    63095.5k
 *     camellia cbc         n/a     75654.3k    76494.6k    76634.0k    76818.7k
 *     aes gcm              n/a     36842.4k    38709.4k    38703.8k    39229.6k
 *     aes ccm              n/a     30888.3k    32445.2k    33016.7k    32948.1k
 *     rsa 512  bit private key             0.370 ms
 *     rsa 512  bit public key (2^16 +1)    0.027 ms
 *     rsa 1024 bit private key             1.740 ms
 *     rsa 1024 bit public key (2^16 +1)    0.080 ms
 *     rsa 2048 bit private key            10.241 ms
 *     rsa 2048 bit public key (2^16 +1)    0.272 ms
 *     rsa 4096 bit private key            70.023 ms
 *     rsa 4096 bit public key (2^16 +1)    0.997 ms
 * 
 *     
 *     ---------------------------------------------------------------------------
 *     
 *     Security provider: IAIK, version 4.0 
 *     Java VM: Sun Microsystems Inc., version 1.6.0_21, JIT (none)
 *     OS: Windows 7/x86, version 6.1
 *     
 *     The 'numbers' are in 1000s of bytes per second processed.
 *     type               8 bytes   64 bytes   256 bytes   1024 bytes   8192 bytes
 *     md2               8893.3k     9036.7k     9058.2k     9099.6k     9106.1k
 *     md5             157235.0k   258273.4k   264262.4k   269773.8k   272694.8k
 *     sha1            113007.2k   149820.5k   162381.8k   164403.8k   165477.8k
 *     sha224           71388.8k    89642.7k    90182.4k    90604.1k    90471.1k
 *     sha256           71430.1k    89559.7k    90286.9k    90847.6k    91004.3k
 *     sha384           37756.7k    41579.4k    42440.9k    42584.9k    42973.3k
 *     sha512           37954.7k    41526.2k    42369.0k    43082.4k    43008.6k
 *     ripe md128      106397.5k   150197.6k   153580.4k   153486.7k   152913.7k
 *     ripe md160       83991.4k   106475.5k   107798.1k   108454.8k   108411.3k
 *     ripe md256      104840.0k   138541.9k   149158.6k   152042.7k   150418.8k
 *     ripe md320       82567.3k   105046.6k   105934.8k   107333.9k   107434.6k
 *     whirlpool        19461.1k    20462.7k    20499.5k    20481.7k    20541.2k
 *     arcfour          76719.5k   121872.0k   130604.8k   132849.9k   134002.1k
 *     des cbc          31987.1k    36371.0k    37005.7k    37068.8k    37166.0k
 *     des ede3 cbc     14186.3k    14923.7k    15097.7k    15083.5k    15107.9k
 *     idea cbc         28797.5k    32259.4k    32818.0k    32869.0k    32966.6k
 *     rc2 cbc          30942.0k    34461.8k    35034.9k    35159.1k    35088.7k
 *     blowfish cbc     49139.4k    60003.6k    61499.9k    62084.4k    62039.9k
 *     rc5 cbc          49724.1k    62544.3k    63782.0k    64207.3k    64453.1k
 *     gost cbc         30831.5k    34448.4k    34927.2k    34985.0k    35031.6k
 *     cast128 cbc      42222.3k    50061.7k    51228.4k    51549.9k    51959.7k
 *     rc6 cbc              n/a     74561.6k    77246.6k    77743.7k    78116.4k
 *     mars cbc             n/a     62746.9k    64262.2k    64691.9k    64904.7k
 *     twofish cbc          n/a     65558.7k    67369.2k    68031.8k    68090.7k
 *     aes cbc              n/a     59362.8k    60546.3k    61159.7k    61434.5k
 *     serpent cbc          n/a     39414.7k    40339.3k    40569.1k    40432.0k
 *     rijndael-256 cbc     n/a     47378.3k    48998.4k    49457.4k    49576.5k
 *     camellia cbc         n/a     45295.9k    46350.4k    46606.4k    46561.9k
 *     aes gcm              n/a     20952.8k    21547.5k    21649.5k    21708.3k
 *     aes ccm              n/a     20429.3k    21434.2k    21600.7k    21744.6k
 *     rsa 512  bit private key             0.888 ms
 *     rsa 512  bit public key (2^16 +1)    0.071 ms
 *     rsa 1024 bit private key             5.001 ms
 *     rsa 1024 bit public key (2^16 +1)    0.243 ms
 *     rsa 2048 bit private key            32.202 ms
 *     rsa 2048 bit public key (2^16 +1)    0.892 ms
 *     rsa 4096 bit private key           231.615 ms
 *     rsa 4096 bit public key (2^16 +1)    3.406 ms
 * 
 * </PRE>
 * <P>
 * 
 * @version File Revision <!-- $$Revision: --> 56 <!-- $ -->
 */
public class TestSpeed {

  private final static boolean DEBUG = iaik.debug.Debug.mode;

  private final static int BUFSIZE = 8192 + 256 + 12; // + 12 for CCM

  private final static int SIZE_NUM = 5;
  private final static int RSA_NUM = 4;

  private final static int D_MD2 = 0;
  private final static int D_MD5 = 1;
  private final static int D_SHA1 = 2;
  private final static int D_SHA224 = 3;
  private final static int D_SHA256 = 4;
  private final static int D_SHA384 = 5;
  private final static int D_RIPEMD128 = 6;
  private final static int D_RIPEMD160 = 7;
  private final static int D_RIPEMD256 = 8;
  private final static int D_RIPEMD320 = 9;
  private final static int D_SHA512 = 10;
  private final static int D_WHIRLPOOL = 11;

  private final static int I_HASHES_FIRST = 0;
  private final static int I_HASHES_LAST = 11;

  private final static int D_CBC_RIJNDAEL = 12;

  private final static int D_GCM_AES = 13;
  private final static int D_CCM_AES = 14;
  private final static int D_CBC_DES = 15;
  private final static int D_CBC_RC2 = 16;
  private final static int D_CBC_BF = 17;
  private final static int D_CBC_RC5 = 18;
  private final static int D_CBC_GOST = 19;
  private final static int D_CBC_CAST128 = 20;
  private final static int D_CBC_RC6 = 21;
  private final static int D_CBC_MARS = 22;
  private final static int D_CBC_TWOFISH = 23;
  private final static int D_ARCFOUR = 24;
  private final static int D_CBC_SERPENT = 25;
  private final static int D_CBC_RIJNDAEL256 = 26;
  private final static int D_CBC_CAMELLIA = 27;
  private final static int D_EDE3_DES = 28;
  private final static int D_CBC_IDEA = 29;

  private static int I_CIPHERS_FIRST = 12;
  private static int I_CIPHERS_LAST = 27;

  private final static int I_CCMGCM_FIRST = 13;
  private final static int I_CCMGCM_LAST = 14;

  // algorithm names to display on screen
  private final static String displayNames[] = { "md2", "md5", "sha1", "sha224", "sha256",
      "sha384", "sha512", "ripe md128", "ripe md160", "ripe md256", "ripe md320", "whirlpool",
      "aes cbc", "aes gcm", "aes ccm", "des cbc", "rc2 cbc", "blowfish cbc", "rc5 cbc", "gost cbc",
      "cast128 cbc", "rc6 cbc", "mars cbc", "twofish cbc", "arcfour", "serpent cbc",
      "rijndael-256 cbc", "camellia cbc", "des ede3 cbc", "idea cbc" };

  private final static int ALGOR_NUM = displayNames.length;

  // algorithm names to use with getInstance()
  private final static String algorithmNames[] = { "MD2", "MD5", "SHA-1", "SHA-224", "SHA-256",
      "SHA-384", "SHA-512", "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320", "WHIRLPOOL",
      "AES/CBC/NoPadding", "AES/GCM/NoPadding", "AES/CCM/NoPadding", "DES/CBC/NoPadding",
      "RC2/CBC/NoPadding", "Blowfish/CBC/NoPadding", "RC5/CBC/NoPadding", "GOST/CBC/NoPadding",
      "CAST128/CBC/NoPadding", "RC6/CBC/NoPadding", "MARS/CBC/NoPadding", "Twofish/CBC/NoPadding",
      "ARCFOUR/ECB/NoPadding", "Serpent/CBC/NoPadding", "Rijndael-256/CBC/NoPadding",
      "Camellia/CBC/NoPadding", "DESede/CBC/NoPadding", "IDEA/CBC/NoPadding", };

  // length of the key in bytes for each of the encryption algorithms
  private final static int keyLengths[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 16, 16, 8, 16,
      16, 16, 32, 16, 16, 16, 16, 16, 16, 16, 16, 24, 16, };

  // instance variables
  private Object[] implementations = new Object[ALGOR_NUM];
  private boolean doit[] = new boolean[ALGOR_NUM];
  private boolean doRSA;

  private Provider provider;
  private String providerName;

  private long sleepTime = 3000;
  private long PREEMPTIVE_TEST_TIME = 200;

  public TestSpeed(boolean rsa, boolean hashes, boolean ciphers, boolean ccmgcm) {
    if (rsa) {
      doRSA = true;
    }
    if (hashes) {
      for (int i = I_HASHES_FIRST; i <= I_HASHES_LAST; i++) {
        doit[i] = true;
      }
    }
    if ((ciphers) || (ccmgcm)) {
      if (ciphers) {
        if (ccmgcm) {
          // ciphers and CCM, GCM
          I_CIPHERS_LAST = I_CCMGCM_LAST;
        }
      } else {
        // CCM, GCM only
        I_CIPHERS_FIRST = I_CCMGCM_FIRST;
        I_CIPHERS_LAST = I_CCMGCM_LAST;
      }
      for (int i = I_CIPHERS_FIRST; i <= I_CIPHERS_LAST; i++) {
        doit[i] = true;
      }
    }
  }

  // constructor for use in development
  public TestSpeed() {
    // RSA
    doRSA = true;

    // message digests
    doit[D_MD2] = true;
    doit[D_MD5] = true;
    doit[D_SHA1] = true;
    doit[D_SHA224] = true;
    doit[D_SHA256] = true;
    doit[D_SHA384] = true;
    doit[D_SHA512] = true;
    doit[D_RIPEMD128] = true;
    doit[D_RIPEMD160] = true;
    doit[D_RIPEMD256] = true;
    doit[D_RIPEMD320] = true;
    doit[D_WHIRLPOOL] = true;

    // stream ciphers
    doit[D_ARCFOUR] = true;

    // block ciphers
    doit[D_CBC_DES] = true;
    doit[D_EDE3_DES] = true;
    doit[D_CBC_IDEA] = true;
    doit[D_CBC_RC2] = true;
    doit[D_CBC_BF] = true;
    doit[D_CBC_RC5] = true;
    doit[D_CBC_GOST] = true;
    doit[D_CBC_CAST128] = true;
    doit[D_CBC_RC6] = true;
    doit[D_CBC_MARS] = true;
    doit[D_CBC_TWOFISH] = true;
    doit[D_CBC_RIJNDAEL] = true;
    doit[D_CBC_SERPENT] = true;
    doit[D_CBC_RIJNDAEL256] = true;
    doit[D_CBC_CAMELLIA] = true;
    doit[D_GCM_AES] = false;
    doit[D_CCM_AES] = false;
  }

  /**
   * Converts the input double number to an appropriate output string format.
   * 
   * @param d
   *          the input double number to be printed
   * @param l
   *          the length of the resulting number string
   * @param k
   *          the number of places behind the decimal point
   * 
   * @return the string representing the converted input double number
   */
  public static String format(double d, int l, int k) {
    String number = Double.toString(d);

    int pos = number.indexOf(46);

    // append zeros after the decimal point?
    int k1 = k - (number.length() - pos - 1);

    pos = Math.min(pos + k + 1, number.length());

    number = number.substring(0, pos);
    int length = number.length();
    if ((length < l) || (k1 > 0)) {
      StringBuffer tmp = new StringBuffer();
      int spaces = l - number.length();
      if (k1 > 0) {
        spaces -= k1;
      }
      for (int i = 0; i < spaces; i++)
        tmp.append(" ");

      tmp.append(number);
      for (int i = 0; i < k1; i++) {
        tmp.append("0");
      }
      number = tmp.toString();
    }

    return number;
  }

  public void setProvider(Provider provider) {
    this.provider = provider;
    providerName = provider.getName();
    Security.insertProviderAt(provider, 2);
  }

  public void setProvider(String providerClassName) throws Exception {
    Class clazz = Class.forName(providerClassName);
    setProvider((Provider) (clazz.newInstance()));
  }

  private boolean testThreads() {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("MD5");
    } catch (Exception e) {
      return false;
    }
    int bufSize = 512;
    byte[] buffer = new byte[bufSize];
    long start, stop;
    int count = 2;
    while (true) {
      start = System.currentTimeMillis();
      for (int i = 0; i < count; i++) {
        md.update(buffer, 0, bufSize);
      }
      stop = System.currentTimeMillis();
      if (stop - start > PREEMPTIVE_TEST_TIME) {
        break;
      }
      count <<= 1;
    }
    // System.out.println("start: " + start);
    // System.out.println("stop: " + stop);
    // System.out.println("Count: " + count);

    SpeedTimer timer = new SpeedTimer("ThreadTest", PREEMPTIVE_TEST_TIME);
    timer.start();
    while (timer.startNow == false) {
      Thread.yield();
    }
    int n = count * 6;
    while ((timer.stopNow == false) && (n > 0)) {
      md.update(buffer, 0, bufSize);
      n--;
    }
    // System.out.println("n: " + n);
    // if( true ) return true;
    // if( true ) return false;

    return (n != 0);
  }

  /**
   * Executes some tests for several algorithms and measures the speed.
   * 
   * <p>
   * Each test goes over several typical block sizes and the results are printed
   * in 1000s of bytes per second processed.
   */
  public void startTest() {
    long start, stop;
    int count;
    int i, j, k;
    double d;
    double[][] results = new double[ALGOR_NUM][SIZE_NUM];
    double[] rsa_results = new double[2 * RSA_NUM];
    RSAPrivateKey privateKey[] = new RSAPrivateKey[RSA_NUM];
    RSAPublicKey publicKey[] = new RSAPublicKey[RSA_NUM];
    Cipher rsa = null;
    SpeedTimer timer = null;

    byte[] buf = new byte[BUFSIZE];
    byte[] outbuf = new byte[BUFSIZE];
    Random random = new Random();
    random.nextBytes(buf);

    System.out.println("To get the most accurate results, try to run this");
    System.out.println("program when this computer is idle.");
    System.out.println();

    if (doRSA) {
      try {
        rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", providerName);
        privateKey[0] = new RSAPrivateKey(test512);
        privateKey[1] = new RSAPrivateKey(test1024);
        privateKey[2] = new RSAPrivateKey(test2048);
        privateKey[3] = new RSAPrivateKey(test4096);
        publicKey[0] = new RSAPublicKey(test512pub);
        publicKey[1] = new RSAPublicKey(test1024pub);
        publicKey[2] = new RSAPublicKey(test2048pub);
        publicKey[3] = new RSAPublicKey(test4096pub);
      } catch (Exception e) {
        System.out.println("Error initializing RSA:");
        System.out.println(e);
        doRSA = false;
      }
    }
    for (i = I_HASHES_FIRST; i <= I_HASHES_LAST; i++) {
      if (doit[i]) {
        try {
          implementations[i] = MessageDigest.getInstance(algorithmNames[i], providerName);
        } catch (Exception e) {
          System.out.println("Could not find message digest " + algorithmNames[i] + " in provider "
              + providerName + ":");
          System.out.println(e);
          doit[i] = false;
        }
      }
    }
    for (i = I_CIPHERS_FIRST; i <= I_CIPHERS_LAST; i++) {
      if (doit[i]) {
        try {
          implementations[i] = Cipher.getInstance(algorithmNames[i], providerName);
        } catch (Exception e) {
          System.out.println("Could not find cipher " + algorithmNames[i] + " in provider "
              + providerName + ":");
          System.out.println(e);
          doit[i] = false;
        }
      }
      if (doit[i]) {
        String keyName = algorithmNames[i].substring(0, algorithmNames[i].indexOf('/'));
        SecretKeySpec keySpec = new SecretKeySpec(key_data, 0, keyLengths[i], keyName);
        Key newKey = keySpec;
        try {
          SecretKeyFactory kf = SecretKeyFactory.getInstance(keyName, providerName);
          newKey = kf.generateSecret(keySpec);
        } catch (Exception e) {
          // ignore
        }
        try {
          Cipher cipher = (Cipher) implementations[i];
          int blockSize = cipher.getBlockSize();
          if (cipher.getAlgorithm().indexOf("ECB") == -1) {
            int ivSize;
            if (cipher.getAlgorithm().indexOf("CCM") == -1) {
              ivSize = (blockSize > 0) ? blockSize : 1;
            } else {
              ivSize = 8;
            }
            IvParameterSpec params = new IvParameterSpec(new byte[ivSize]);
            cipher.init(Cipher.ENCRYPT_MODE, newKey, params);
            // cipher.init(Cipher.DECRYPT_MODE, newKey, params);
          } else {
            cipher.init(Cipher.ENCRYPT_MODE, newKey);
          }
        } catch (Exception e) {
          System.out.println("Error initializing cipher " + algorithmNames[i] + ":");
          System.out.println(e);
          doit[i] = false;
        }
      }
    }

    try {
      // wait for harddisc to calm down, etc.
      Thread.sleep(1000);
      System.out.println();

      boolean preemptiveThreads = testThreads();
      if (preemptiveThreads) {
        System.out.println("Preemptive thread scheduler detected.");
      } else {
        System.out.println("Thread scheduler is not preemptive!");
      }
      System.out.println();

      for (i = I_HASHES_FIRST; i <= I_HASHES_LAST; i++) {
        if (doit[i]) {
          MessageDigest md = (MessageDigest) implementations[i];
          System.out.println("Doing " + displayNames[i] + " for " + sleepTime / 1000.0
              + " seconds each:");
          for (j = 0; j < SIZE_NUM; j++) {
            System.out.print("  on " + lengths[j] + " byte blocks: ");
            if (preemptiveThreads) {
              count = 0;
              timer = new SpeedTimer("Timer " + algorithmNames[i], sleepTime);
              timer.start();
              while (timer.startNow == false) {
                Thread.yield();
              }
              start = System.currentTimeMillis();
              while (timer.stopNow == false) {
                md.update(buf, 0, lengths[j]);
                count++;
              }
              stop = System.currentTimeMillis();
            } else {
              int target = 8;
              while (true) {
                count = 0;
                start = System.currentTimeMillis();
                while (count < target) {
                  md.update(buf, 0, lengths[j]);
                  count++;
                }
                stop = System.currentTimeMillis();
                if (stop - start >= PREEMPTIVE_TEST_TIME) {
                  break;
                }

                target <<= 1;
              }
              double factor = ((double) sleepTime) / (stop - start);
              if (factor > 1.2) {
                target = (int) (target * factor);
                start = System.currentTimeMillis();
                count = 0;
                while (count < target) {
                  md.update(buf, 0, lengths[j]);
                  count++;
                }
                stop = System.currentTimeMillis();
              }
            }
            d = (stop - start) / 1000.0;
            results[i][j] = count / d * lengths[j];
            System.out.print(count + " " + displayNames[i] + "'s in " + d + "s");
            System.out.println(" (" + format(results[i][j] / 1000.0, 16, 1).trim() + " k/s)");
          }
          System.out.println();
        }
      }

      for (i = I_CIPHERS_FIRST; i <= I_CIPHERS_LAST; i++) {
        if (doit[i]) {
          Cipher cipher = (Cipher) implementations[i];
          int blockSize = cipher.getBlockSize();
          System.out.println("Doing " + displayNames[i] + " for " + sleepTime / 1000.0
              + " seconds each:");
          for (j = 0; j < SIZE_NUM; j++) {
            System.out.print("  on " + lengths[j] + " byte blocks: ");
            if (lengths[j] < blockSize) {
              System.out.println("blocks too small, skipping");
              continue;
            }
            if (preemptiveThreads) {
              count = 0;
              timer = new SpeedTimer("Timer " + algorithmNames[i], sleepTime);
              timer.start();
              while (timer.startNow == false) {
                Thread.yield();
              }
              start = System.currentTimeMillis();
              while (timer.stopNow == false) {
                cipher.update(buf, 0, lengths[j], outbuf, 0);
                count++;
              }
              cipher.doFinal(buf, 0, lengths[j], outbuf, 0);
              stop = System.currentTimeMillis();
            } else {
              int target = 8;
              while (true) {
                count = 0;
                start = System.currentTimeMillis();
                while (count < target) {
                  cipher.doFinal(buf, 0, lengths[j], outbuf, 0);
                  count++;
                }
                stop = System.currentTimeMillis();
                if (stop - start >= PREEMPTIVE_TEST_TIME) {
                  break;
                }
                target <<= 1;
              }
              double factor = ((double) sleepTime) / (stop - start);
              if (factor > 1.2) {
                target = (int) (target * factor);
                start = System.currentTimeMillis();
                count = 0;
                while (count < target) {
                  cipher.update(buf, 0, lengths[j], outbuf, 0);
                  count++;
                }
                cipher.doFinal(buf, 0, lengths[j], outbuf, 0);
                stop = System.currentTimeMillis();
              }
            }
            d = (stop - start) / 1000.0;
            results[i][j] = count / d * lengths[j];
            System.out.print(count + " " + displayNames[i] + "'s in " + d + "s");
            System.out.println(" (" + format(results[i][j] / 1000000.0, 16, 1).trim() + " m/s)");
          }
          System.out.println();
        }
      }

      // RSA

      if (doRSA) {
        int countPrivate = 0;
        long startPrivate = 0, stopPrivate = 0;
        for (j = 0; j < RSA_NUM; j++) {
          rsa.init(Cipher.ENCRYPT_MODE, publicKey[j]);
          if (preemptiveThreads) {
            System.out.print("Doing " + rsa_bits[j] + " bit rsa's for " + sleepTime / 1000.0
                + "s: ");
            // first public key operation
            count = 0;
            byte[] ciphertext = null;
            timer = new SpeedTimer("Timer RSA", sleepTime);
            timer.start();
            while (timer.startNow == false) {
              Thread.yield();
            }
            start = System.currentTimeMillis();
            while (timer.stopNow == false) {
              ciphertext = rsa.doFinal(key_data16);
              count++;
            }
            stop = System.currentTimeMillis();
            // then private key operation
            rsa.init(Cipher.DECRYPT_MODE, privateKey[j]);
            if (ciphertext != null) {
              countPrivate = 0;
              timer = new SpeedTimer("Timer RSA", sleepTime);
              timer.start();
              while (timer.startNow == false) {
                Thread.yield();
              }
              startPrivate = System.currentTimeMillis();
              while (timer.stopNow == false) {
                rsa.doFinal(ciphertext);
                countPrivate++;
              }
              stopPrivate = System.currentTimeMillis();
            }
          } else {
            System.out.print("Doing " + rsa_bits[j] + " bit rsa's: ");
            // public key operation first
            int target = 1;
            byte[] ciphertext = null;
            while (true) {
              count = 0;
              start = System.currentTimeMillis();
              while (count < target) {
                ciphertext = rsa.doFinal(key_data16);
                count++;
              }
              stop = System.currentTimeMillis();
              if (stop - start >= PREEMPTIVE_TEST_TIME) {
                break;
              }
              target <<= 1;
            }
            double factor = ((double) sleepTime) / (stop - start);
            if (factor > 1.2) {
              target = (int) (target * factor);
              start = System.currentTimeMillis();
              count = 0;
              while (count < target) {
                ciphertext = rsa.doFinal(key_data16);
                count++;
              }
              stop = System.currentTimeMillis();
            }
            // then public key operations
            rsa.init(Cipher.DECRYPT_MODE, privateKey[j]);
            if (ciphertext != null) {
              target = 1;
              while (true) {
                countPrivate = 0;
                startPrivate = System.currentTimeMillis();
                while (countPrivate < target) {
                  rsa.doFinal(key_data16);
                  countPrivate++;
                }
                stopPrivate = System.currentTimeMillis();
                if (stopPrivate - startPrivate >= PREEMPTIVE_TEST_TIME) {
                  break;
                }
                target <<= 1;
              }
              factor = ((double) sleepTime) / (stopPrivate - startPrivate);
              if (factor > 1.2) {
                target = (int) (target * factor);
                startPrivate = System.currentTimeMillis();
                countPrivate = 0;
                while (countPrivate < target) {
                  rsa.doFinal(key_data16);
                  countPrivate++;
                }
                stopPrivate = System.currentTimeMillis();
              }
            }
          }
          d = (stop - start) / 1000.0;
          double dPrivate = (stopPrivate - startPrivate) / 1000.0;
          System.out.println(countPrivate + " " + rsa_bits[j]
              + " bit RSA's private key operations in " + dPrivate + "s");
          System.out.println(count + " " + rsa_bits[j]
              + " bit RSA's public key (2^16 +1) operations in " + d + "s");
          rsa_results[j] = d / count;
          rsa_results[j + RSA_NUM] = dPrivate / countPrivate;
          if ((d > 10) || (dPrivate > 10)) // computer is too slow
            break;
        }
      }
    } catch (Exception ex) {
      ex.printStackTrace();
      // System.out.println("Exception: "+ex);
      return;
    }

    System.out.println();
    System.out.println("Security provider: " + provider.getName() + ", version "
        + provider.getVersion());
    String jit = System.getProperty("java.compiler", "");
    if (jit.length() == 0) {
      jit = "(none)";
    }
    System.out.println("Java VM: " + System.getProperty("java.vendor") + ", version "
        + System.getProperty("java.version") + ", JIT " + jit);
    System.out.println("OS: " + System.getProperty("os.name") + "/" + System.getProperty("os.arch")
        + ", version " + System.getProperty("os.version"));
    System.out.println();

    System.out.println("The 'numbers' are in 1000s of bytes per second processed.");
    System.out.print("type               ");
    for (j = 0; j < SIZE_NUM; j++) {
      System.out.print(lengths[j] + " bytes" + "   ");
    }
    System.out.println();

    int displayCount = ALGOR_NUM;
    if (I_CIPHERS_LAST != I_CCMGCM_LAST) {
      // if CCM/GCM have not been tested, do not display them
      displayCount -= (I_CCMGCM_LAST - I_CCMGCM_FIRST + 1);
    }
    for (k = 0; k < displayCount; k++) {
      String name = "                ";
      name = displayNames[k].concat(name.substring(displayNames[k].length()));

      System.out.print(name);
      for (j = 0; j < SIZE_NUM; j++) {
        double result = results[k][j];
        if (result > 10000) {
          System.out.print(format(result / 1000.0, 8, 1) + "k   ");
        } else if (result > 0.01) {
          System.out.print(format(result, 8, 1) + "    ");
        } else {
          System.out.print("     n/a    ");
        }
      }
      System.out.println();
    }

    if (doRSA) {
      for (k = 0; k < RSA_NUM; k++) {
        int rsaBits = rsa_bits[k];
        String spaces = (rsaBits == 512) ? "  " : " ";
        System.out.println("rsa " + rsaBits + spaces + "bit private key          "
            + format(1000 * rsa_results[k + RSA_NUM], 8, 3) + " ms");
        System.out.println("rsa " + rsaBits + spaces + "bit public key (2^16 +1) "
            + format(1000 * rsa_results[k], 8, 3) + " ms");
      }
    } else {
      System.out.println("rsa: n/a");
    }
  }

  /**
   * Processes various algorithm implementations to measure the speed.
   */
  public static void main(String args[]) {

    TestSpeed testSpeed;
    String provider = null;

    boolean rsa = false;
    boolean hashes = false;
    boolean ciphers = false;
    boolean ccmgcm = false;
    int time = -1;
    for (int i = 0; i < args.length; i++) {
      String arg = args[i].toLowerCase();
      if (arg.equals("rsa")) {
        rsa = true;
      } else if (arg.startsWith("hash")) {
        hashes = true;
      } else if (arg.startsWith("cipher")) {
        ciphers = true;
      } else if (arg.startsWith("ccmgcm")) {
        ccmgcm = true;
      } else if (arg.equals("all")) {
        rsa = hashes = ciphers = ccmgcm = true;
      } else if (arg.startsWith("p=")) {
        provider = args[i].substring(2);
      } else if (arg.startsWith("t=")) {
        try {
          double d = Double.valueOf(arg.substring(2)).doubleValue();
          time = (int) (d * 1000);
        } catch (NumberFormatException e) {
          System.out.println("Expecting number argument to 't='!");
          iaik.utils.Util.waitKey();
          System.exit(1);
        }
      } else {
        System.out.println("Ignoring unknown switch " + args[i]);
      }
    }
    if (rsa || hashes || ciphers || ccmgcm) {
      testSpeed = new TestSpeed(rsa, hashes, ciphers, ccmgcm);
    } else {
      if (DEBUG) {
        testSpeed = new TestSpeed();
      } else {
        testSpeed = new TestSpeed(true, true, true, false);
      }
    }
    if (provider == null) {
      provider = "iaik.security.provider.IAIK";
      // provider = "sun.security.provider.Sun";
    }
    if (time > 0) {
      testSpeed.sleepTime = time;
    }
    try {
      testSpeed.setProvider(provider);
      testSpeed.startTest();
    } catch (Throwable e) {
      System.out.println("Error conducting speed tests:");
      e.printStackTrace();
      // System.out.println(e);
    }
    iaik.utils.Util.waitKey();
  }

  // constant test data stuff (keys, etc.)
  private final static byte[] key_data16 = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
      (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0, (byte) 0x34, (byte) 0x56, (byte) 0x78,
      (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0, (byte) 0x12, };
  private final static byte[] key_data = { (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
      (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0, (byte) 0x34, (byte) 0x56, (byte) 0x78,
      (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0, (byte) 0x12, (byte) 0x12, (byte) 0x34,
      (byte) 0x56, (byte) 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0, (byte) 0x34,
      (byte) 0x56, (byte) 0x78, (byte) 0x9a, (byte) 0xbc, (byte) 0xde, (byte) 0xf0, (byte) 0x12, };

  private final static int[] lengths = { 8, 64, 256, 1024, 8192 };

  private final static int[] rsa_bits = { 512, 1024, 2048, 4096 };

  private final static byte[] test512, test1024, test2048, test4096;

  private final static byte[] test512pub, test1024pub, test2048pub, test4096pub;

  // these are base64 encoded for significantly smaller class files
  static {
    String _test512 = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAtSiEFPqApzHaO76G"
        + "EEbxzV5NdoeGVCGlUatzTSvxyVJkR9ayhr2CtMPpbbY44GvjZfbWZfCHsVd/utKg"
        + "cVXd7wIDAQABAkB+WXTN4O2MLzQDiV2dyq1pTEWAzwM8eH8CWC9B+s1XWKhGAvsL"
        + "tz+ZSEl+LXhyjhUTsq7w4Qkt+nudu1gPsSFRAiEA3I82itht9DUc4zBFCcMgbCjM"
        + "VKEFNKIXXwsoaU8/SUcCIQDSRIXTdzW/QUGaf2xuYoKeDulhBlFw07HyQXBUBtWa"
        + "GQIgGbfxajtWhvVyiuNkCYFhVHtlaDDmhH6qLwEEE1OUU50CIGJmqvJRoZeFpHv3"
        + "Efl+pH3voIxFdquEhoxGz5ijMidRAiEAy5xclCPnrLz2ElLT2+Rfa2JviV5xdCS2" + "yJqsnOcprBs=";
    String _test512pub = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALUohBT6gKcx2ju+hhBG8c1eTXaHhlQh"
        + "pVGrc00r8clSZEfWsoa9grTD6W22OOBr42X21mXwh7FXf7rSoHFV3e8CAwEAAQ==";

    String _test1024 = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMrrOwh97qb8a4SR"
        + "YulkcnvBamw1ttnOteggnY1VZTYrapGshv/5FKvXA2ojwjutwsX3mHgrfbAWJHIu"
        + "vwiETrPBi10CkHIt/zKhs/Dg4iV05pRnnHDpTvkT/+9KRJCI/yod/OZYNKKcpefW"
        + "tbYjybENz5o87iMmVtis/VkGRq9HAgMBAAECgYBoxVfvpIYKdh5VjnORqilqOI1o"
        + "XbuRbieCOQTgKo1dkMEvgfMaS1Me/p9muBvbkHYWnSZ+NYZp2qTqx7QfA6FWR2Kn"
        + "w3b4eleMEtDFz02d5i3DaBsDxH8jvNG49hmKc401toybGu047Iapw/3fUD/H8/Pm"
        + "1I8fjQyylVupKuFhUQJBAOY80mY6qnflJdZejJKvse2Ig081Sx70FHbxKbES8eiZ"
        + "3udI+C9iKyCv5d7ztNJwjN0qVWAgRwqR678V3VklOw0CQQDhn9yHUAvCoUWXzm82"
        + "2rpvDftiKbeQvqoeIOZ+j0K+TAP+iNMvQBOEIoFpGzUIyYRk+CpVo9ck6+uwKxGm"
        + "XO6jAkAWpFKYpRpQkiNncoLmhgq8blljd708fQpqLAtKk69gjYlDO4TUvBW7sDCt"
        + "/U+CBnmD4n7k5ie2XWVOtGrBMo0dAkAewPCJTSLdO6hFwfCs1HGXE5vRTIhl5WdA"
        + "xhFE7PgXAjuFJVdL2HsQhreHARtggD9Yl+8FT1jTAolUsPot5/rrAkAP8C5u4/sD"
        + "RKOg9ew6EdFJ+fmXShBlMULAzlVUrhHYitB7ZUSkswOl1gdlKD/oJzDVkcaXWZWg" + "7Z7/0R7dlYm7";
    String _test1024pub = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDK6zsIfe6m/GuEkWLpZHJ7wWps"
        + "NbbZzrXoIJ2NVWU2K2qRrIb/+RSr1wNqI8I7rcLF95h4K32wFiRyLr8IhE6zwYtd"
        + "ApByLf8yobPw4OIldOaUZ5xw6U75E//vSkSQiP8qHfzmWDSinKXn1rW2I8mxDc+a"
        + "PO4jJlbYrP1ZBkavRwIDAQAB";

    String _test2048 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCWAbjDgHCwQG/Y"
        + "F4oQcfJJTLZ6ML9L0++I5Liay0Vvf7CuFKbjAzaePijxUl3wzhsutv5a+4lCcCgF"
        + "WBb7KGhAbv0xroIoPHUZ2NcAw2I10vOzaK7yg3NGhjrgGSlZyXm/ng4pXP0cvEik"
        + "CD2tA2eItxJBhaAFPDwJ5IMX5r96heDJhOWtEoY4J0ZiiTi3AVk/ex2QAgG7uXVn"
        + "WkThuH8V7GMLNhDvYqf9N7gJBBEWZ6w0vpsTdwJklqdgifBgeySzecDZ5tqvu4qT"
        + "z+d+m74VWyHaWAqT2cVvGbmA9SbKCMrOVgDdvgr2dbhMOu4CFzWFH3i/bKNJNDL/"
        + "l8igQe+3AgMBAAECggEBAI6X0GS3QWepuSe3KJz9VA1tiMCaeh3AtyBwGzO6KqUU"
        + "woSYSRPeyBqgiBbt7zKrGZfMh/lAxneLWd/Knv3cqU0mtDR36G4LGl2ZjLfDAyab"
        + "AuH2juclIX1Wt7yy7mXVaZBG1LtpE4ovSPX0h3xhkheZvxbdyQFxArl8qUkdJcN2"
        + "7lGX0wo77mqK5mg6y53/XKYeHruTObU4Y3hfGIdhzq1/CIwLDDE7zj5P6Va5mblK"
        + "2n9rgoCCJFF78isg+Wk9mP5Od0wXN0C2E/4Bd8/NOob54QCBv2ymjaYje5A7voyZ"
        + "1ksYAlEMZIdonrfyb7S1LYnCYcITzENOwODJrCsLHmECgYEA046k4DFzWn/fi1Yl"
        + "X7sqNGFvJFwKh2fEIKG2Y/JaElPi1h3vROCafrcps5hK7JqyNi6mUH5yW4Go2BT6"
        + "Bz+nxpFwEsYFai1mGuaKcsuqHYPYZDJ2EiRvgor6giUNmV8iMG4UVNH9e9VhPSNJ"
        + "8SnFsFvqyTKqWt09+pMMwsFix78CgYEAtYTyyj5GQGEd73QadNqPNmZS5Wn4lx2i"
        + "G22RVXjntRvb8g1F6JVNpjY1b1x4BEuxkPiqbQjECL8UF95ubynzzBTO4tJ1cSq6"
        + "AxnfpSJNFP/7os/4QmzgKd722Q91UcQN3h4nRKshwOjtEpOOV3l/S+oxxSeQyhCk"
        + "JA9uxZUBlgkCgYBaqPVlEiwB62yr9IXdqYKjoeGULlFgx4oYBdT4reIFmqdJ5Ngl"
        + "py7uAKZBTZFGJeEbMRCazCVLq5vkxdCEDLZkdO0XTn8BimUIQCWyni7PqTGxdqJ8"
        + "kdqrkc1aunBCeq9XG8VguACt8bpTDe1hCOqr8igCgtDYUZl+6Ud9qowfVwKBgAdr"
        + "it03lHmXPrkGHvq94HLR1fuozE+pF3JVlUZQLfCaVfBcGIp8Z/MubhrCRemvCnAp"
        + "qhXQ8OqGnRSotAz5Qw0JoLdm8QQSQg5UZW8DqvD70daC99wHRVaQ1bhjyGDySbrV"
        + "src846FWJDLJM11iCxEYXrZ3epS3/22178pF4A25AoGBAMKg0iU6JbpgScqGUXzA"
        + "MJ7Qyy4YLNiQhsPTskSifaxaE93UB+eSZPA2w1YQ0gL8U9NujWWgmzaBW6AFwu2X"
        + "bzhX7Tpq5FlXcz7g2SWXdtFovEYLT2zmCNUXpCaty7Qu7E3xFSLSmQGWX6+4nlI2"
        + "f6LWNjVcwmpTiGjraZ9sW26B";
    String _test2048pub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlgG4w4BwsEBv2BeKEHHy"
        + "SUy2ejC/S9PviOS4mstFb3+wrhSm4wM2nj4o8VJd8M4bLrb+WvuJQnAoBVgW+yho"
        + "QG79Ma6CKDx1GdjXAMNiNdLzs2iu8oNzRoY64BkpWcl5v54OKVz9HLxIpAg9rQNn"
        + "iLcSQYWgBTw8CeSDF+a/eoXgyYTlrRKGOCdGYok4twFZP3sdkAIBu7l1Z1pE4bh/"
        + "FexjCzYQ72Kn/Te4CQQRFmesNL6bE3cCZJanYInwYHsks3nA2ebar7uKk8/nfpu+"
        + "FVsh2lgKk9nFbxm5gPUmygjKzlYA3b4K9nW4TDruAhc1hR94v2yjSTQy/5fIoEHv" + "twIDAQAB";

    String _test4096 = "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"
        + "bmfeqRw1uNWCxiBi5OiCf7rQn8T8F5M=";
    String _test4096pub = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAulxo2PvkGjniHUvjADNp"
        + "KvPjPhUlhvUgLDBq1arZaPYFaq6bYCeV7CIbI1poN1O/uTzSPG+OLrjDoOECTC2a"
        + "M3KqqCc6S6XkTw99E0HogGFKni22CMVGgcVf134GzL5m8wtwLoYDlb5MVdUjdV85"
        + "fJd8dXQxZ1s6Vi9fc2Rk2b2Vj4VFaH4rEoNbaidsxe2jXK295CpmLrh9a/HjWthg"
        + "zcIya4yohDb84OT+MPkoyJ+0aHLvKbsXtiHH6PRbWxBj+7m63K8bwplihKMylnRu"
        + "URRCQcwj043tKayZ6fqvTkSbSmYRqZzhQEHz2aprU6uVMsFCG+/ExaBGXRmVG/sA"
        + "WzglbPYxQ9mbk+QOAWNe7w5FRuot/TpCwjcCH1wz4M7T7P6O6MWwMZpv35jlnIuN"
        + "V+19xieAgd9sd7S+CSn3ZwgaM+qpYwm6vAQLcmLk6IvnJhLPagi81NmZhJSpd9Sp"
        + "olz0XyIq/462b3gzd8LlugdGS5dR4BmGdJJOO9CUmHDIrSeywGjqZjCNYbGGndax"
        + "OxBMnKX43Sj9JgkEHEd1RGiDFbAiZgHDGEO3gKQT+eeZT/942DxUsDPuw2EMrVFE"
        + "HAvExDhGO+HMLxmVswKSRmvaPTZOUoTwEuz8uA3mLckOdJsQQPRq+PvxK1hEGjSJ"
        + "6Vmes8uliZKGYrygKU26rjECAwEAAQ==";

    test512 = Util.decodeByteArray(_test512);
    test1024 = Util.decodeByteArray(_test1024);
    test2048 = Util.decodeByteArray(_test2048);
    test4096 = Util.decodeByteArray(_test4096);
    test512pub = Util.decodeByteArray(_test512pub);
    test1024pub = Util.decodeByteArray(_test1024pub);
    test2048pub = Util.decodeByteArray(_test2048pub);
    test4096pub = Util.decodeByteArray(_test4096pub);
  }
}

class SpeedTimer extends Thread {

  private long sleepTime;

  volatile boolean startNow;
  volatile boolean stopNow;

  SpeedTimer(String name, long sleepTime) {
    super(name);
    this.sleepTime = sleepTime;
    startNow = false;
    stopNow = false;
  }

  public void run() {
    try {
      startNow = false;
      stopNow = false;
      Thread.sleep(100);
      startNow = true;
      Thread.sleep(sleepTime);
      startNow = false;
      stopNow = true;
    } catch (InterruptedException e) {
      System.out.println(e);
    }
  }
}
