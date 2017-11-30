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

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11Key;
import iaik.pkcs.pkcs7.RSACipherProvider;

/**
 * This is a RSACipherProvider for the PKCS#7 implementation of the IAIK-JCE. It uses the key unwrap
 * feature of the PKCS#11 cipher class to decrypt the secret key of the enveloped PKCS#7 data.
 * <p>
 * The <code>PKCS7DecryptionDemoWithUnwrapRSACipherProvider</code> demo uses this class.
 * 
 * @author Karl Scheibelhofer
 * 
 * 
 */
class UnwrapRSACipherProvider extends RSACipherProvider {

  /**
   * Create a RSA cipher provider for PKCS#7 which uses the spcified JCE providers for encryption
   * (ENCRYPT_MODE) and decryption operations (DECRYPT_MODE).
   * 
   * @param cipherEncryptProvider
   *          The JCE provider to use for encryption.
   * @param cipherDecryptProvider
   *          The JCE provider to use for decryption.
   * 
   * 
   */
  protected UnwrapRSACipherProvider(String cipherEncryptProvider,
      String cipherDecryptProvider) {
    super(cipherEncryptProvider, cipherDecryptProvider);
  }

  /**
   * If the mode is decryption (DECRYPT_MODE) and the key is a PKCS#11 key (IAIKPKCS11Key), this
   * implementation uses the <code>Cipher.unwrap()</code> method to decrypt the symmetric key. For
   * all other cases, it delegates the operation to the superclass.
   */
  protected byte[] cipher(int mode, Key key, byte[] data) throws GeneralSecurityException {
    byte[] cipherResult;

    if (key instanceof IAIKPKCS11Key) {
      Cipher pkcs11RsaCipher;
      if (mode == DECRYPT_MODE) {
        if (cipherDecryptProvider_ == null) {
          pkcs11RsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        } else {
          pkcs11RsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",
              cipherDecryptProvider_);
        }
        pkcs11RsaCipher.init(Cipher.UNWRAP_MODE, key);
        Key secretKey = pkcs11RsaCipher.unwrap(data, IAIKPKCS11Key.DESede,
            Cipher.SECRET_KEY);
        cipherResult = secretKey.getEncoded();
        // Key value is sensitive and can't be encoded --> call default super method
        if (cipherResult == null) {
          cipherResult = super.cipher(mode, key, data);
        }
      } else {
        throw new NoSuchAlgorithmException("Illegal mode for RSA cipher algorithm: "
            + mode);
      }
    } else {
      cipherResult = super.cipher(mode, key, data);
    }

    return cipherResult;
  }

}
