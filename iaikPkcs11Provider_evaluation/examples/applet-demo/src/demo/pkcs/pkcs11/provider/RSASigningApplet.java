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
import java.applet.Applet;
import java.awt.Button;
import java.awt.Label;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Random;

import iaik.pkcs.pkcs11.provider.Constants;
import iaik.pkcs.pkcs11.provider.DefaultLoginManager;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11;
import iaik.pkcs.pkcs11.provider.IAIKPkcs11Exception;
import iaik.pkcs.pkcs11.provider.keys.IAIKPKCS11RsaPrivateKey;
import iaik.security.provider.IAIK;

/**
 * This class shows a short demonstration of how to use this provider implementation for digital
 * signing. It offers two actions: key pair generation and signing. Algorithm is fixed to RSA and
 * the data to be signed are fixed to the text "This is some data to be signed.".
 * 
 */
public class RSASigningApplet extends Applet implements ActionListener {

  /**
   * The data that will be signed. A real application would e.g. read it from file.
   */
  protected final static byte[] DATA = "This is some data to be signed.".getBytes();

  /**
   * A modified version of DATA. Used to ensure that signature does not verify with modified data.
   */
  protected final static byte[] MODIFIED_DATA = "That is some data to be signed."
      .getBytes();

  /**
   * The PKCS#11 JCE provider.
   */
  protected IAIKPkcs11 iaikPkcs11Provider_;

  /**
   * The IAIK JCE software provider.
   */
  protected IAIK iaikSoftwareProvider_;

  /**
   * The PKCS#11 signature key.
   */
  protected PrivateKey signatureKey_;

  /**
   * This is the key used for verifying the signature. In contrast to the signature key, this key is
   * a software key and holds the actual keying material directly.
   */
  protected PublicKey verificationKey_;

  /**
   * Here the actual signature is stored compliant with PKCS#1
   */
  protected byte[] signature_;

  /**
   * Button texts for the applet's actions.
   */
  String actionSign_ = "Sign something";
  String actionCreateKey_ = "Create RSA KeyPair";

  /**
   * The applet's GUI objects.
   */
  TextArea textArea1_;
  TextField textFieldInput1_;
  TextField textFieldInput2_;
  TextField textFieldInput3_;
  TextField textFieldInput4_;
  Button doSigningButton_;
  Button doCreateButton_;

  /**
   * Empty constructor.
   */
  public RSASigningApplet() { /* empty */
  }

  /**
   * Initialize this applet. Builds the GUI and registers the IAIK software provider.
   */
  public void init() {
    System.out.println("initializing... ");

    iaikPkcs11Provider_ = null;

    setSize(400, 800);

    // to be allowed to install security providers, the applet must be signed
    if ((iaikSoftwareProvider_ = (IAIK) Security.getProvider("IAIK")) == null) {
      iaikSoftwareProvider_ = new IAIK();
      Security.addProvider(iaikSoftwareProvider_);
    }

    System.out.println("registered providers:");
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      System.out.println("at position " + i + ": " + providers[i]);
    }

    System.out.println("...finished initializing");
    System.out.flush();

    Panel modulePanel = new Panel();
    Label label1 = new Label("PKCS#11 module path: ");
    textFieldInput1_ = new TextField(20);
    modulePanel.add(label1);
    modulePanel.add(textFieldInput1_);

    Panel wrapperPanel = new Panel();
    Label label2 = new Label("Absolute path to PKCS#11 wrapper native library: ");
    textFieldInput2_ = new TextField(20);
    wrapperPanel.add(label2);
    wrapperPanel.add(textFieldInput2_);

    Panel slotPanel = new Panel();
    Label label3 = new Label("Index of slot to be used: ");
    textFieldInput3_ = new TextField(20);
    slotPanel.add(label3);
    slotPanel.add(textFieldInput3_);

    add(modulePanel);
    add(wrapperPanel);
    add(slotPanel);

    textFieldInput1_.setText("modulelibrary.dll");
    textFieldInput2_.setText("/path-to/pkcs11wrapper.dll");
    textFieldInput3_.setText("0");

    Panel buttonPanel = new Panel();
    doCreateButton_ = new Button(actionCreateKey_);
    doCreateButton_.addActionListener(this);
    buttonPanel.add(doCreateButton_);

    doSigningButton_ = new Button(actionSign_);
    doSigningButton_.addActionListener(this);
    buttonPanel.add(doSigningButton_);

    add(buttonPanel);

    Panel signaturePanel = new Panel();
    textArea1_ = new TextArea("Signature = ");
    signaturePanel.add(textArea1_);
    add(signaturePanel);

    Panel statusPanel = new Panel();
    Label label4 = new Label("Status:");
    textFieldInput4_ = new TextField(40);
    statusPanel.add(label4);
    statusPanel.add(textFieldInput4_);
    add(statusPanel);
    textFieldInput4_.setText("initialized");

  }

  /**
   * Instantiates the PKCS#11 provider using the given properties. Then performs the chosen action
   * (signing or key pair creation).
   */
  public void actionPerformed(ActionEvent arg0) {
    String action = arg0.getActionCommand();

    // some resetting
    textArea1_.setText("Signature = ");
    signatureKey_ = null;
    textFieldInput4_.setText("pending ...");

    String module = textFieldInput1_.getText();
    String wrapperPath = textFieldInput2_.getText();
    String slotIndexString = textFieldInput3_.getText();
    if (module != null && wrapperPath != null && slotIndexString != null) {
      boolean initialized = false;
      try {
        Integer.parseInt(slotIndexString);
        getProviderInstance(module, wrapperPath, "[" + slotIndexString + "]");
        initialized = true;
      } catch (NumberFormatException e) {
        e.printStackTrace();
        textFieldInput4_.setText("error: given slot-index is not a valid number");
      } catch (IAIKPkcs11Exception e) {
        e.printStackTrace();
        textFieldInput4_.setText("error: could not create PKCS#11 provider instance, "
            + e.getMessage());
      } catch (Exception e) {
        e.printStackTrace();
        textFieldInput4_.setText("error during provider instantiation: "
            + e.getClass().toString() + ": " + e.getMessage());
      }
      if (initialized) {

        if (action.equals(actionSign_)) {
          try {
            textFieldInput4_.setText("Signing ...");
            signing();
          } catch (GeneralSecurityException e) {
            e.printStackTrace();
            if (e.getMessage().contains("Found no signature key")) {
              textFieldInput4_.setText("error during signing: found no signature key");
            }
            textFieldInput4_.setText("error during signing: " + e.getMessage());
          } catch (IOException e) {
            e.printStackTrace();
            textFieldInput4_.setText("error during signing: " + e.getMessage());
          } catch (Exception e) {
            e.printStackTrace();
            textFieldInput4_.setText("error during signing: " + e.getClass().toString()
                + ": " + e.getMessage());
          }
        } else {// actionCreateKey_
          try {
            textFieldInput4_.setText("Generating key pair ...");
            CreateKeystoreEntryDemo.main(new String[] { module, wrapperPath,
                "[" + slotIndexString + "]", "RSA" });
            textFieldInput4_.setText("Key pair generated.");
          } catch (Exception e) {
            e.printStackTrace();
            textFieldInput4_.setText("error during key pair creation: " + e.getMessage());
          }
        }
      }

    } else {
      textFieldInput4_.setText("error: module, wrapper-path or slot-index empty");
    }
  }

  /**
   * Instantiate the PKCS#11 provider using the given parameters.
   * 
   * @param module
   *          the PKCS#11 module to be used
   * @param wrapperPath
   *          path to the PKCS#11 wrapper native library
   * @param slotIndex
   *          slot index to be used
   * @throws IAIKPkcs11Exception
   *           if PKCS#11 provider instantiation fails
   */
  private void getProviderInstance(String module, String wrapperPath, String slotIndex)
      throws IAIKPkcs11Exception {
    if (iaikPkcs11Provider_ != null) {
      Properties curProps = iaikPkcs11Provider_.getProperties();
      String nativeModuleSet = curProps.getProperty(Constants.PKCS11_NATIVE_MODULE);
      String wrapperPathSet = curProps.getProperty(Constants.PKCS11_WRAPPER_PATH);
      String slotIndexSet = curProps.getProperty(Constants.SLOT_ID);
      // we can reuse a suitable provider instance
      if (nativeModuleSet.equals(module) && wrapperPathSet.equals(wrapperPath)
          && slotIndexSet.equals(slotIndex)) {
        // Set the login manager for this applet instance.
        // If we do not do this, the login-dialog may freez in some versions of
        // the Java plug-in. The plug-in may have disposed components of the dialogs.
        iaikPkcs11Provider_.setLoginManager(new DefaultLoginManager());
        if (Security.getProvider(iaikPkcs11Provider_.getName()) == null) {
          Security.addProvider(iaikPkcs11Provider_);
        }
        return;
      } else {
        Security.removeProvider(iaikPkcs11Provider_.getName());
        IAIKPkcs11.discardProviderInstance(iaikPkcs11Provider_);
      }
    }

    Properties pkcs11ProviderConfig = new Properties();

    // add or overwrite module, wrapperPath and slot
    pkcs11ProviderConfig.setProperty(Constants.PKCS11_NATIVE_MODULE, module);
    pkcs11ProviderConfig.setProperty(Constants.PKCS11_WRAPPER_PATH, wrapperPath);
    pkcs11ProviderConfig.setProperty(Constants.SLOT_ID, slotIndex);

    iaikPkcs11Provider_ = new IAIKPkcs11(pkcs11ProviderConfig);
    Security.addProvider(iaikPkcs11Provider_);
    System.out.println("created PKCS#11 provider instance");

  }

  /**
   * Creates and verifies the signature.
   * 
   * @throws GeneralSecurityException
   * @throws IOException
   */
  public void signing() throws GeneralSecurityException, IOException {
    System.out.println("signing... ");

    getSignatureKeyPair();
    signData();
    verifySignature();
    verifySignatureWithModifiedData();
    verifyModifiedSignature();
    logout();
    System.err.flush();

    System.out.println("...finished signing");
    System.out.flush();

    textFieldInput4_.setText("finished signing");
  }

  /**
   * Stop this applet. Does effectively nothing.
   */
  public void stop() {
    System.out.print("stopping... ");
    System.out.println("stopped");
    System.out.flush();
  }

  /**
   * Destroy this applet. Removes the JCA providers registered by this applet.
   */
  public void destroy() {
    System.out.print("preparing for unloading...");
    try {
      if (iaikPkcs11Provider_ != null) {
        Security.removeProvider(iaikPkcs11Provider_.getName());
        IAIKPkcs11.discardProviderInstance(iaikPkcs11Provider_);
      }
      Security.removeProvider(iaikSoftwareProvider_.getName());
    } catch (Throwable ex) {
      ex.printStackTrace();
    }

    System.out.println("registered providers:");
    Provider[] providers = Security.getProviders();
    for (int i = 0; i < providers.length; i++) {
      System.out.println("at position " + i + ": " + providers[i]);
    }

    System.out.println("finished unloading");
    System.out.flush();
  }

  /**
   * This method creates a key store for the configured PKCS#11 token and simply takes the first RSA
   * signing key entry. The keys are stored in the member variables <code>signatureKey_
   * </code> and <code>verificationKey_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   * @exception IOException
   *              If loading the key store fails.
   */
  public void getSignatureKeyPair() throws GeneralSecurityException, IOException {
    // with this call we just get an uninitialized PKCS#11 key store, it is not bound to a
    // specific IAIKPkcs11 provider instance after this call, even if you specify the provider
    // at this call. this is a limitation of SUN's KeyStore concept. the KeyStoreSPI object
    // has no chance to get its own provider instance.
    KeyStore tokenKeyStore = KeyStore.getInstance("PKCS11KeyStore",
        iaikPkcs11Provider_.getName());

    if (tokenKeyStore == null) {
      System.out
          .println("Got no key store. Ensure that the provider is properly configured and installed.");
      throw new GeneralSecurityException(
          "Got no key store. Ensure that the provider is properly configured and installed.");
    }
    // now load the correct token
    ByteArrayInputStream providerNameInpustStream = new ByteArrayInputStream(
        iaikPkcs11Provider_.getName().getBytes("UTF-8"));
    tokenKeyStore.load(providerNameInpustStream, null);

    Enumeration aliases = tokenKeyStore.aliases();

    // and we take the first signature (private) key for simplicity
    while (aliases.hasMoreElements()) {
      String keyAlias = aliases.nextElement().toString();
      if (tokenKeyStore.isKeyEntry(keyAlias)) {
        Key key = tokenKeyStore.getKey(keyAlias, null);
        if (key instanceof IAIKPKCS11RsaPrivateKey) {
          Certificate[] certificateChain = tokenKeyStore.getCertificateChain(keyAlias);
          if (certificateChain != null && certificateChain.length != 0) {
            X509Certificate signerCertificate = (X509Certificate) certificateChain[0];
            boolean[] keyUsage = signerCertificate.getKeyUsage();
            if ((keyUsage == null) || keyUsage[0] || keyUsage[1]) { // check for digital signature
                                                                    // or
                                                                    // non-repudiation, but also
                                                                    // accept if none set
              System.out.println("##########");
              System.out.println("The signature key is: " + key);
              System.out.println("##########");
              // get the corresponding certificate for this signature key
              System.out.println("##########");
              System.out.println("The signer certificate is:");
              System.out.println(signerCertificate.toString());
              System.out.println("##########");
              signatureKey_ = (PrivateKey) key;
              verificationKey_ = signerCertificate.getPublicKey();
              break;
            }
          }
        }
      }
    }

    if (signatureKey_ == null) {
      System.out.println("Found no signature key. Ensure that a valid card is inserted.");
      throw new GeneralSecurityException(
          "Found no signature key. Ensure that a valid card is inserted.");
    }
  }

  /**
   * This method signs the data in the byte array <code>DATA</code> with <code>signatureKey_</code>.
   * Normally the data would be read from file. The created signature is stored in
   * <code>signature_</code>.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void signData() throws GeneralSecurityException {
    // Get a signature object from our new provider, we explicitly say that we
    // want to generate the hash outside the card. Otherwise the default
    // configuration from the property file is used.
    Signature signatureEngine = Signature.getInstance("ExternalSHA1WithRSA",
        iaikPkcs11Provider_.getName());

    // initialize for signing with our signature key that we got from
    // the keystore
    signatureEngine.initSign(signatureKey_);

    // put the data that should be signed
    System.out.println("##########");
    System.out.println("The data to be signed is: \"" + new String(DATA) + "\"");
    System.out.println("##########");
    signatureEngine.update(DATA);

    // get the signature
    signature_ = signatureEngine.sign();

    System.out.println("##########");
    System.out.println("The signature is:");
    System.out.println(new BigInteger(1, signature_).toString(16));
    System.out.println("##########");

    textArea1_.setText("Signature = " + new BigInteger(1, signature_).toString(16));
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifySignature() throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    Signature signatureEngine = Signature.getInstance("SHA1withRSA",
        iaikSoftwareProvider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    signatureEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    signatureEngine.update(DATA);

    // verify the signature
    boolean verified = signatureEngine.verify(signature_);

    System.out.println("##########");
    System.out.println("Trying to verify signature with original data.");
    if (verified) {
      System.out.println("The signature was verified successfully");
    } else {
      System.out.println("The signature was forged or the data was modified!");
    }
    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifySignatureWithModifiedData() throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    Signature signatureEngine = Signature.getInstance("SHA1withRSA",
        iaikSoftwareProvider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    signatureEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    signatureEngine.update(MODIFIED_DATA);

    // verify the signature
    boolean verified = signatureEngine.verify(signature_);

    System.out.println("##########");
    System.out.println("Trying to verify signature with modified data.");
    if (verified) {
      System.out.println("The signature was verified successfully.");
    } else {
      System.out.println("The signature was forged or the data was modified!");
    }
    System.out.println("##########");
  }

  /**
   * This method verifies the signature stored in <code>signatureKey_
   * </code>. The verification key used is <code>verificationKey_</code>. The implementation for the
   * signature algorithm is taken from an other provider. Here IAIK is used, IAIK is pure software.
   * 
   * @exception GeneralSecurityException
   *              If anything with the provider fails.
   */
  public void verifyModifiedSignature() throws GeneralSecurityException {
    // get a signature object from the software-only provider for verification
    Signature signatureEngine = Signature.getInstance("SHA1withRSA",
        iaikSoftwareProvider_.getName());

    // initialize for verification with our verification key that we got from
    // the certificate
    signatureEngine.initVerify(verificationKey_);

    // put the original data that claims to be signed
    signatureEngine.update(DATA);

    // create a modified signature
    byte[] modifiedSignature = createModified(signature_);

    // verify the signature
    boolean verified = false;
    System.out.println("##########");
    System.out.println("Trying to verify modified signature.");
    try {
      verified = signatureEngine.verify(modifiedSignature);
    } catch (SignatureException ex) {
      verified = false;
    }

    if (verified) {
      System.out.println("The signature was verified successfully.");
    } else {
      System.out.println("The signature was forged or the data was modified!");
    }
    System.out.println("##########");
  }

  /**
   * Create a modified version of the given data. This method returns the original byte array with
   * one randomly selected bit flipped.
   * 
   * @param originalData
   *          The original to create a modified version from. The original data is not modified.
   * @return The modified version of the given data.
   */
  public byte[] createModified(byte[] originalData) {
    if (originalData == null) {
      return null;
    }
    if (originalData.length == 0) {
      return new byte[0];
    }
    BigInteger originalInteger = new BigInteger(1, originalData); // create a positiv big integer
    int selectedBit = new Random().nextInt(originalData.length * 8); // select one bit randomly
    BigInteger modifiedInteger = originalInteger.flipBit(selectedBit); // invert selected bit

    return modifiedInteger.toByteArray();
  }

  /**
   * This method logs out the user from the underlying token. This causes subsequent operations to
   * login the user again if required. Remind that the application must read private objects (e.g.
   * private keys) from the keystore again after a logout - login. In general, it does not work to
   * use private key objects from a previous login. This may work with some PKCS#11 modules but not
   * with others.
   */
  void logout() {
    iaikPkcs11Provider_.getTokenManager().getKeyStore().logout();
  }

}
