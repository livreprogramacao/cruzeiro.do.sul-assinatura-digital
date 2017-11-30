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

package demo.pkcs.pkcs11.provider;

// class and interface imports
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;

import iaik.pkcs.PKCSException;

/**
 * This class shows how to decrpyt data according to PKCS#7 using the PKCS#11 provider. This
 * implementation uses the RSACipherProvider feature of the PKCS#7 implementation of the IAIK-JCE.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
public class PKCS7DecryptionDemoWithUnwrapRSACipherProvider extends
    PKCS7DecryptionDemoWithRSACipherProvider {

  /**
   * This empty constructor registers the new provider to the Java security system.
   */
  public PKCS7DecryptionDemoWithUnwrapRSACipherProvider(String fileToBeDecrypted,
      String outputFile) {
    super(fileToBeDecrypted, outputFile);
  }

  /**
   * This is the main method that is called by the JVM during startup.
   * 
   * @param args
   *          These are the command line arguments.
   */
  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      printUsage();
      throw new GeneralSecurityException("invalid parameters");
    }
    String fileToBeDecrypted = args[0];
    String outputFile = args[1];

    PKCS7DecryptionDemoWithUnwrapRSACipherProvider demo = new PKCS7DecryptionDemoWithUnwrapRSACipherProvider(
        fileToBeDecrypted, outputFile);

    demo.getKeyStore();
    demo.getDecryptionKey();
    demo.decrypt();
    System.out.flush();
    System.err.flush();
  }

  /**
   * This method decrypts the data from the provided encrypted PKCS#7 file. It uses the info in the
   * member variables set by <code>getDecryptionKey()</code>. Moreover, it writes the decrypted data
   * to the specified output file.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception FileNotFoundException
   *              If the data file could not be found.
   * @exception PKCSException
   *              If parsing the PKCS#7 file fails.
   */
  public void decrypt() throws GeneralSecurityException, IOException, PKCSException {
    System.out.println("##########");
    System.out.print("Decrypting data... ");

    // setup cipher engine for decryption
    recipientInfo_.setRSACipherProvider(new UnwrapRSACipherProvider(null, pkcs11Provider_
        .getName()));
    envelopedData_.setupCipher(decryptionKey_, recipientInfoIndex_);

    // read all data and write to output file
    FileOutputStream outputStream = new FileOutputStream(outputFile_);
    InputStream dataInput = envelopedData_.getInputStream();
    byte[] buffer = new byte[4096];
    int bytesRead;
    while ((bytesRead = dataInput.read(buffer)) >= 0) {
      // write to output
      outputStream.write(buffer, 0, bytesRead);
    }

    outputStream.flush();
    outputStream.close();

    System.out.println("finished");
    System.out.println("##########");
  }

  /**
   * Print information how to use this demo class.
   */
  public static void printUsage() {
    System.out
        .println("Usage: PKCS7DecryptionDemoWithRSACipherProvider <file to decrypt> <output file>");
    System.out
        .println(" e.g.: PKCS7DecryptionDemoWithRSACipherProvider encryptedData.p7 decryptedData.dat");
  }

}
