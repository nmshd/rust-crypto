package com.example.vulcans_limes;


import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * This class provides the method declarations that are the interface for the JNI.
 * The first part are Rust-methods that can be called from other Java-classes,
 * while the second part contains full Java-methods that can be called from Rust.
 * <p>
 * This class also loads the compiled Rust coda as a dynamic library
 * <p>
 * All methods defined in this class hava to have a corresponding method defined in lib.rs,
 * with the same method name and corresponding input and output parameters, according to this table:
 * <p>
 * Rust     	        Java
 * ------------------------
 * i32                 int
 * bool     	        boolean
 * char      	        char
 * i8   	            byte
 * f32   	            float
 * f64   	            double
 * i64   	            long
 * i16   	            short
 * String    	        String
 * Vec<T> 	             ArrayList<T>
 * Box<[u8]> 	        byte[]
 * jni::JObject<'env>  (any Java object as input type)
 * jni::jobject 	    (any Java object as output)
 *
 * @noinspection unused - Methods called from Rust are not recognized as being in use
 */
class RustDef {

    /*
    CryptoManger object for execution of methods
     */
    static CryptoManager cryptoManager;

    static {
        // This call loads the dynamic library containing the Rust code.
        System.loadLibrary("vulcanslimes");
    }

    //----------------------------------------------------------------------------------------------
    //Rust methods that can be called from Java

    /**
     * Proof of concept - shows type conversion
     * DO NOT USE
     */
    static native ArrayList<String> special(ArrayList<Integer> input1, int input2);

    /**
     * Proof of concept method - shows callback from Rust to a java method
     * ONLY USE FOR TESTING
     */
    static native String callRust();

    static native byte[] demoEncrypt(byte[] data);

    static native void demoCreate(String key_id, String key_gen_info);

    static native void demoInit();

    static native byte[] demoDecrypt(byte[] data);

    static native byte[] demoSign(byte[] data);

    static native boolean demoVerify(byte[] data);

    static native void demoLoad(String key_id);

    //----------------------------------------------------------------------------------------------
    //Java methods that can be called from Rust

    /*
     Proof of concept method - get called from Rust when callRust() gets called
        DO NOT USE
     */
    static void callback() {
        System.out.println("Callback successful");
    }

    /**
     * Creates a new cryptographic key identified by {@code key_id}.
     * <p>
     * This method generates a new cryptographic key within the TPM. The key is made persistent
     * and associated with the provided {@code key_id}, which uniquely identifies the key
     * so that it can be retrieved later for cryptographic operations.
     *
     * @param key_id     a String that uniquely identifies the key to be created within the TPM.
     * @param keyGenInfo additional information required for key generation, specifying parameters such as
     *                   key size, algorithm, or other configuration details.
     * @throws InvalidAlgorithmParameterException if the specified key generation parameters are invalid or
     *                                            incompatible with the key generation process.
     * @throws CertificateException               if there is an issue with certificate handling, such as failures
     *                                            in certificate creation or validation.
     * @throws IOException                        if an I/O error occurs during key generation or processing.
     * @throws NoSuchAlgorithmException           if the requested cryptographic algorithm for key generation is
     *                                            not available or supported.
     * @throws KeyStoreException                  if there is an error accessing the keystore, such as a failure
     *                                            to store the newly generated key.
     * @throws NoSuchProviderException            if the requested security provider is not available or supported.
     */
    static void create_key(String key_id, String keyGenInfo) throws InvalidAlgorithmParameterException, CertificateException,
            IOException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException {
        if (keyGenInfo.contains("RSA")) cryptoManager.generateKeyPair(key_id, keyGenInfo);
        else cryptoManager.genKey(key_id, keyGenInfo);
    }

    /**
     * Loads an existing cryptographic key identified by {@code key_id}.
     * <p>
     * This method loads an existing cryptographic key from the TPM. The loaded key is
     * associated with the provided {@code key_id}, which uniquely identifies the key
     * so that it can be retrieved later for cryptographic operations.
     *
     * @param key_id a String that uniquely identifies the key to be loaded from the TPM.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore, typically due to
     *                                   incorrect or inaccessible key information.
     * @throws KeyStoreException         if there is an error accessing the keystore, such as a failure to load
     *                                   or initialize the keystore.
     */
    static void load_key(String key_id) throws UnrecoverableKeyException, KeyStoreException {
        cryptoManager.loadKey(key_id);
    }

    /**
     * Initializes the TPM (Trusted Platform Module) module and returns a handle for further operations.
     * <p>
     * This method initializes the TPM context and prepares it for use. It should be called before performing
     * any other operations with the TPM. Upon initialization, it sets up the necessary configurations and
     * resources required for cryptographic operations involving the TPM.
     *
     * @throws KeyStoreException if the KeyStore Provider does not exist or fails to initialize, indicating issues
     *                           with the key store setup process.
     */
    static void initialize_module() throws KeyStoreException {
        cryptoManager = new CryptoManager();

    }

    /**
     * Signs the given data using the key managed by the TPM.
     * <p>
     * This method signs the provided data using the key managed by the TPM (Trusted Platform Module). The data to be
     * signed is represented as a byte array. The signing process produces a signature for the data, which is returned as
     * a byte array containing the signed data.
     *
     * @param data a byte array representing the data to be signed.
     * @return the signed data as a byte array.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore.
     * @throws NoSuchAlgorithmException  if the requested algorithm is not available.
     * @throws KeyStoreException         if there is an error accessing the keystore.
     * @throws SignatureException        if the signature process encounters an error.
     * @throws InvalidKeyException       if the key used for signing is invalid.
     * @throws InvalidKeySpecException   if the key specification is invalid.
     * @throws NoSuchProviderException   if the provider is not available.
     */
    static byte[] sign_data(byte[] data) throws UnrecoverableKeyException, NoSuchAlgorithmException,
            KeyStoreException, SignatureException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException {
        return cryptoManager.signData(data);
    }

    /**
     * Verifies the signature of the given data using the key managed by the TPM.
     * <p>
     * This method verifies the signature of the provided data against a known signature using the key managed by the TPM
     * (Trusted Platform Module). Both the data and the signature are represented as byte arrays. The verification process
     * validates whether the signature matches the data, returning true if the signature is valid and false otherwise.
     *
     * @param data      a byte array representing the data to be verified.
     * @param signature a byte array representing the signature to be verified against the data.
     * @return true if the signature is valid, false otherwise.
     * @throws SignatureException        if the signature verification process encounters an error.
     * @throws KeyStoreException         if there is an error accessing the keystore.
     * @throws NoSuchAlgorithmException  if the requested algorithm is not available.
     * @throws InvalidKeyException       if the key used for verification is invalid.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore.
     * @throws InvalidKeySpecException   if the key specification is invalid.
     * @throws NoSuchProviderException   if the provider is not available.
     */
    static boolean verify_signature(byte[] data, byte[] signature) throws SignatureException, KeyStoreException,
            NoSuchAlgorithmException, InvalidKeyException, UnrecoverableKeyException, InvalidKeySpecException,
            NoSuchProviderException {
        return cryptoManager.verifySignature(data, signature);
    }

    /**
     * Encrypts the given data using the key managed by the TPM.
     * <p>
     * This method encrypts the provided data using the key managed by the TPM (Trusted Platform Module).
     * The data to be encrypted is represented as a byte array. The encryption process is performed using cryptographic
     * operations managed by the {@link CryptoManager}. The encrypted data is returned as a byte array.
     * <p>
     * This method is called from Rust code, indicating that it may be invoked as part of an integration with a Rust
     * application or library.
     *
     * @param data a byte array representing the data to be encrypted.
     * @return a byte array containing the encrypted data.
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid for encryption.
     * @throws UnrecoverableKeyException          if the key cannot be recovered from the keystore.
     * @throws NoSuchPaddingException             if the padding scheme is not available.
     * @throws IllegalBlockSizeException          if the block size is invalid for the encryption algorithm.
     * @throws CertificateException               if there is an issue loading the certificate chain.
     * @throws NoSuchAlgorithmException           if the requested algorithm is not available.
     * @throws IOException                        if there is an I/O error during the operation.
     * @throws KeyStoreException                  if there is an error accessing the keystore.
     * @throws BadPaddingException                if the data padding is incorrect for encryption.
     * @throws InvalidKeySpecException            if the key specification is invalid.
     * @throws InvalidKeyException                if the key is invalid for encryption.
     * @throws NoSuchProviderException            if the provider is not available.
     */
    static byte[] encrypt_data(byte[] data) throws InvalidAlgorithmParameterException, UnrecoverableKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException,
            IOException, KeyStoreException, BadPaddingException, InvalidKeySpecException, InvalidKeyException,
            NoSuchProviderException {
        return cryptoManager.encryptData(data);
    }

    /**
     * Decrypts the given data using the key managed by the TPM.
     * <p>
     * This method decrypts the provided encrypted data using the key managed by the TPM (Trusted Platform Module).
     * The encrypted data is represented as a byte array. The decryption process is performed using cryptographic
     * operations managed by the {@link CryptoManager}. The decrypted data is returned as a byte array.
     * <p>
     * This method is called from Rust code, indicating that it may be invoked as part of an integration with a Rust
     * application or library.
     *
     * @param encrypted_data a byte array representing the data to be decrypted.
     * @return a byte array containing the decrypted data.
     * @throws InvalidAlgorithmParameterException if the algorithm parameters are invalid for decryption.
     * @throws UnrecoverableKeyException          if the key cannot be recovered from the keystore.
     * @throws NoSuchPaddingException             if the padding scheme is not available.
     * @throws IllegalBlockSizeException          if the block size is invalid for the decryption algorithm.
     * @throws CertificateException               if there is an issue loading the certificate chain.
     * @throws NoSuchAlgorithmException           if the requested algorithm is not available.
     * @throws IOException                        if there is an I/O error during the operation.
     * @throws KeyStoreException                  if there is an error accessing the keystore.
     * @throws BadPaddingException                if the data padding is incorrect for decryption.
     * @throws InvalidKeySpecException            if the key specification is invalid.
     * @throws InvalidKeyException                if the key is invalid for decryption.
     * @throws NoSuchProviderException            if the provider is not available.
     */
    static byte[] decrypt_data(byte[] encrypted_data) throws InvalidAlgorithmParameterException, UnrecoverableKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, CertificateException, NoSuchAlgorithmException,
            IOException, KeyStoreException, BadPaddingException, InvalidKeySpecException, InvalidKeyException,
            NoSuchProviderException {
        return cryptoManager.decryptData(encrypted_data);
    }
}