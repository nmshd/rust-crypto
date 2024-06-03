package com.example.vulcans_limes;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class CryptoManager {
    // TODO: READ AND APPROVE JAVADOC
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private final KeyStore keyStore;
    private String KEY_NAME;

    /**
     * Constructs a new instance of {@code CryptoManager} with the default Android KeyStore.
     * <p>
     * This constructor initializes the {@code CryptoManager} with the default Android KeyStore. The Android KeyStore
     * provides a secure storage facility for cryptographic keys and certificates. Upon construction, the key store is
     * initialized, enabling the {@code CryptoManager} to interact with cryptographic keys securely stored on the
     * Android device. If the initialization of the key store fails, a {@link KeyStoreException} is thrown, indicating
     * issues with the key store setup process.
     *
     * @throws KeyStoreException if the KeyStore Provider does not exist or fails to initialize, indicating issues with
     *                           the key store setup process.
     */
    public CryptoManager() throws KeyStoreException {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
    }

    /**
     * Generates a new symmetric key and saves it into the Android KeyStore.
     * <p>
     * This method initializes a new symmetric key for encryption and decryption purposes using the specified symmetric key algorithm.
     * The key is stored in the Android KeyStore and supports various configurations including the choice of encryption algorithms,
     * key sizes, block modes, and padding schemes.
     * Additionally, this method ensures that the key is backed by the strong box feature.
     *
     * @param key_id     The unique identifier under which the key will be stored in the KeyStore.
     * @param keyGenInfo A string containing key generation parameters separated by semicolons. Expected format: "KEY_ALGORITHM;KEY_SIZE;BLOCK_MODE;PADDING".
     * @throws CertificateException               if there is an issue loading the certificate chain.
     * @throws IOException                        for I/O errors such as incorrect passwords.
     * @throws NoSuchAlgorithmException           if the generation algorithm does not exist or the keystore doesn't exist.
     * @throws NoSuchProviderException            if the provider does not exist.
     * @throws InvalidAlgorithmParameterException for invalid or nonexistent parameters.
     * @throws KeyStoreException                  if there is an error accessing the keystore.
     */
    public void genKey(String key_id, String keyGenInfo) throws CertificateException,
            IOException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, KeyStoreException {
        String[] keyGenInfoArr = keyGenInfo.split(";");
        String KEY_ALGORITHM = keyGenInfoArr[0];
        int KEY_SIZE = Integer.parseInt(keyGenInfoArr[1]);
        String BLOCKING = keyGenInfoArr[2];
        String PADDING = keyGenInfoArr[3];

        KEY_NAME = key_id;
        keyStore.load(null);

        // Check if a key with the given key_id already exists
        if (keyStore.containsAlias(KEY_NAME)) {
            throw new KeyStoreException("Key with name " + KEY_NAME + " already exists.");
        }
        KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEY_STORE);
        keyGen.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT |
                        KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(KEY_SIZE)
                .setBlockModes(BLOCKING)
                .setEncryptionPaddings(PADDING)
                .setIsStrongBoxBacked(true)
                .build());
        keyGen.generateKey();
    }

    /**
     * Encrypts the given data using a symmetric key stored in the Android KeyStore.
     * <p>
     * This method takes plaintext data as input and encrypts it using a symmetric key retrieved from the Android KeyStore.
     * The encryption process supports supports GCM, CBC and CTR transformations. A new initialization vector (IV)
     * is generated and the IV is prepended to the ciphertext. The method initializes a
     * {@link Cipher} instance with the appropriate transformation, loads the Android KeyStore, retrieves the symmetric key, and then
     * initializes the cipher in encryption mode with the retrieved key and the generated IV. Finally, the plaintext data is encrypted
     * using the cipher's {@code doFinal} method, and the resulting ciphertext is returned as a byte array.
     *
     * @param data The plaintext data to be encrypted, represented as a byte array.
     * @return A byte array representing the encrypted data, with the IV prepended in the case of GCM mode.
     * @throws NoSuchPaddingException    if the requested padding scheme is not available.
     * @throws NoSuchAlgorithmException  if the requested algorithm is not available.
     * @throws CertificateException      if there is an issue loading the certificate chain.
     * @throws IOException               if there is an I/O error during the operation.
     * @throws InvalidKeyException       if the key cannot be cast to a SecretKey.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore.
     * @throws KeyStoreException         if there is an error accessing the keystore.
     * @throws IllegalBlockSizeException if the data length is invalid for the encryption algorithm.
     * @throws BadPaddingException       if the data could not be padded correctly for encryption.
     * @throws InvalidKeySpecException   if the key specification is invalid.
     * @throws NoSuchProviderException   if the requested security provider is not available.
     */
    public byte[] encryptData(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException,
            CertificateException, IOException, InvalidKeyException, UnrecoverableKeyException,
            KeyStoreException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException,
            NoSuchProviderException {

        keyStore.load(null);
        SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
        String TRANSFORMATION = buildTransformation(secretKey);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] iv = cipher.getIV();

        if (TRANSFORMATION.contains("/GCM/")) {
            assert iv.length == 12; // GCM standard IV size is 12 Byte
        } else {
            assert iv.length == 16; // CBC & CTR standard IV size is 16 Byte
        }
        byte[] encryptedData = cipher.doFinal(data);
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedData.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        return byteBuffer.array();
    }

    /**
     * Decrypts the given encrypted data using a symmetric key stored in the Android KeyStore.
     * <p>
     * This method takes encrypted data as input and decrypts it using a symmetric key retrieved from the Android KeyStore.
     * The decryption process supports GCM, CBC and CTR transformations. The initialization vector (IV)
     * is extracted from the beginning of the encrypted data. The method initializes a {@link Cipher} instance with the appropriate
     * transformation, loads the Android KeyStore, retrieves the symmetric key, and initializes the cipher in decryption mode with the
     * retrieved key and the extracted IV. Finally, the encrypted data is decrypted using the cipher's {@code doFinal} method, and the
     * original plaintext data is returned as a byte array.
     *
     * @param encryptedData The encrypted data to be decrypted, represented as a byte array.
     * @return A byte array representing the decrypted data.
     * @throws NoSuchPaddingException             if the requested padding scheme is not available.
     * @throws NoSuchAlgorithmException           if the requested algorithm is not available.
     * @throws CertificateException               if there is an issue loading the certificate chain.
     * @throws IOException                        if there is an I/O error during the operation.
     * @throws InvalidAlgorithmParameterException if the IV parameter is invalid.
     * @throws InvalidKeyException                if the key cannot be cast to a SecretKey.
     * @throws UnrecoverableKeyException          if the key cannot be recovered from the keystore.
     * @throws KeyStoreException                  if there is an error accessing the keystore.
     * @throws IllegalBlockSizeException          if the data length is invalid for the decryption algorithm.
     * @throws BadPaddingException                if the data could not be padded correctly for decryption.
     * @throws InvalidKeySpecException            if the key specification is invalid.
     * @throws NoSuchProviderException            if the requested security provider is not available.
     */
    public byte[] decryptData(byte[] encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException,
            CertificateException, IOException, InvalidAlgorithmParameterException, InvalidKeyException,
            UnrecoverableKeyException, KeyStoreException, IllegalBlockSizeException, BadPaddingException,
            InvalidKeySpecException, NoSuchProviderException {
        keyStore.load(null);
        SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
        String TRANSFORMATION = buildTransformation(secretKey);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);
        byte[] iv;
        if (TRANSFORMATION.contains("/GCM/")) {
            iv = new byte[12]; // GCM standard IV size
            byteBuffer.get(iv);
            encryptedData = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedData);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv); // 128 is the recommended TagSize
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
        } else {
            iv = new byte[16]; // CBC & CTR standard IV size
            byteBuffer.get(iv);
            encryptedData = new byte[byteBuffer.remaining()];
            byteBuffer.get(encryptedData);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        }
        return cipher.doFinal(encryptedData);
    }

    /**
     * Generates a new asymmetric key pair and saves it into the Android KeyStore.
     * <p>
     * This method generates a new asymmetric key pair suitable for signing and verifying digital signatures.
     * The key pair is stored in the Android KeyStore, leveraging the platform's secure storage capabilities.
     * The method configures the key pair generator with specific parameters, like the digest algorithms to be supported,
     * the signature padding scheme, and whether the key is backed by the strong box feature for enhanced security.
     * The generated key pair consists of a private key for signing and a corresponding public key for verification.
     * The supported algorithms are RSA and EC. The keyGenInfo String should have the following form:
     * For RSA: RSA;key size;hash;padding
     * For EC: EC;curve;hash
     *
     * @param key_id The unique identifier under which the key pair will be stored in the KeyStore.
     * @throws CertificateException               if there is an issue creating the certificate for the key pair.
     * @throws IOException                        for I/O errors such as incorrect passwords.
     * @throws NoSuchAlgorithmException           if the generation algorithm does not exist or the keystore doesn't exist.
     * @throws InvalidAlgorithmParameterException for invalid or nonexistent parameters.
     * @throws NoSuchProviderException            if the provider does not exist.
     * @throws KeyStoreException                  if there is an error accessing the keystore or the key name is already used.
     */
    public void generateKeyPair(String key_id, String keyGenInfo) throws CertificateException, IOException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException,
            KeyStoreException {
        String[] keyGenInfoArr = keyGenInfo.split(";");
        String KEY_ALGORITHM = keyGenInfoArr[0];
        String HASH = keyGenInfoArr[2];

        KEY_NAME = key_id;
        keyStore.load(null);

        // Check if a key with the given key_id already exists
        if (keyStore.containsAlias(KEY_NAME)) {
            throw new KeyStoreException("Key with name " + KEY_NAME + " already exists.");
        }

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEY_STORE);
        if (KEY_ALGORITHM.contains("EC")) {
            String CURVE = keyGenInfoArr[1];
            keyPairGen.initialize(
                    new KeyGenParameterSpec.Builder(
                            KEY_NAME,
                            KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(new ECGenParameterSpec(CURVE))
                            .setDigests(HASH)
                            .build());

        } else {
            int KEY_SIZE = Integer.parseInt(keyGenInfoArr[1]);
            String PADDING = keyGenInfoArr[3];
            keyPairGen.initialize(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setKeySize(KEY_SIZE)
                    .setDigests(HASH)
                    .setSignaturePaddings(PADDING)
                    .setIsStrongBoxBacked(true)
                    .build());
        }
        keyPairGen.generateKeyPair();
    }

    /**
     * Signs the given data using a private key stored in the Android KeyStore.
     * <p>
     * This method takes plaintext data as input and signs it using a private key retrieved from the Android KeyStore.
     * The signing process uses a predefined signature algorithm. The method initializes a {@link Signature} instance with this algorithm,
     * loads the Android KeyStore, retrieves the private key, and then initializes the signature object in sign mode with the retrieved private key.
     * The plaintext data is then updated into the signature object, and finally, the data is signed using the signature object's {@code sign} method.
     * The resulting signature is returned as a byte array.
     *
     * @param data The plaintext data to be signed, represented as a byte array.
     * @return A byte array representing the signature of the data.
     * @throws NoSuchAlgorithmException  if the requested algorithm is not available.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore.
     * @throws KeyStoreException         if there is an error accessing the keystore.
     * @throws InvalidKeyException       if the key cannot be cast to a PrivateKey.
     * @throws SignatureException        if the signature cannot be processed.
     */
    public byte[] signData(byte[] data) throws NoSuchAlgorithmException, UnrecoverableKeyException,
            KeyStoreException, InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchProviderException, CertificateException, IOException {
        keyStore.load(null);
        Signature signature = Signature.getInstance(buildSignatureAlgorithm((PrivateKey) keyStore.getKey(KEY_NAME, null)));
        signature.initSign((PrivateKey) keyStore.getKey(KEY_NAME, null));
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies the signature of the given data using a public key stored in the Android KeyStore.
     * <p>
     * This method verifies the signature of the given data against a known signature. The verification process
     * uses a predefined signature algorithm. The method initializes a {@link Signature} instance with this algorithm,
     * loads the Android KeyStore, retrieves the public key associated with the known signature, and then initializes
     * the signature object in verify mode with the retrieved public key. The plaintext data is then updated into the
     * signature object, and finally, the signature is verified using the signature object's {@code verify} method with
     * the provided signed bytes. The method returns true if the signature is valid, indicating that the data has not
     * been tampered with and was indeed signed by the holder of the corresponding private key; otherwise, it returns false.
     *
     * @param data        The plaintext data whose signature is to be verified, represented as a byte array.
     * @param signedBytes The signature of the data to be verified, represented as a byte array.
     * @return True if the signature is valid, false otherwise.
     * @throws SignatureException        if the signature cannot be processed.
     * @throws InvalidKeyException       if the key cannot be cast to a PublicKey.
     * @throws KeyStoreException         if there is an error accessing the keystore.
     * @throws NoSuchAlgorithmException  if the requested algorithm is not available.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore.
     * @throws InvalidKeySpecException   if the key specification is invalid or cannot be retrieved.
     * @throws NoSuchProviderException   if the provider is not available.
     */
    public boolean verifySignature(byte[] data, byte[] signedBytes) throws SignatureException, InvalidKeyException,
            KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeySpecException, NoSuchProviderException, CertificateException, IOException {
        keyStore.load(null);
        Signature verificationSignature = Signature.getInstance(buildSignatureAlgorithm((PrivateKey) keyStore.getKey(KEY_NAME, null)));
        verificationSignature.initVerify(keyStore.getCertificate(KEY_NAME).getPublicKey());
        verificationSignature.update(data);
        return verificationSignature.verify(signedBytes);
    }

    /**
     * Sets the `KEY_NAME` to the provided key identifier.
     * <p>
     * This method assigns the `KEY_NAME` field with the given `key_id`.
     * This is typically used before loading a key with the specified identifier.
     * It ensures that the `KEY_NAME` is set correctly for subsequent cryptographic operations
     * involving the specified key.
     *
     * @param key_id The unique identifier of a key to be set as `KEY_NAME`.
     */
    public void loadKey(String key_id) throws KeyStoreException, UnrecoverableKeyException, CertificateException, IOException, NoSuchAlgorithmException {
        keyStore.load(null);
        if (keyStore.containsAlias(key_id)) KEY_NAME = key_id;
        else
            throw new UnrecoverableKeyException("The key alias '" + key_id + "' does not exist in the KeyStore.");
    }

    /**
     * Constructs the transformation string for a given key, which is used to initialize a {@link Cipher} instance.
     * <p>
     * This method loads the Android KeyStore and retrieves key-specific metadata using {@link KeyInfo}. From those it builds a transformation string based on the key's algorithm, block modes, and padding schemes. The transformation
     * string follows the format "algorithm/block-mode/padding". It supports both symmetric keys ({@link SecretKey}) and asymmetric keys
     * ({@link PrivateKey}). For symmetric keys, it retrieves encryption paddings; for asymmetric keys, it retrieves signature paddings.
     *
     * @param key The key for which the transformation string is to be built. It can be either a {@link SecretKey} or a {@link PrivateKey}.
     * @return A string representing the transformation in the format "algorithm/mode/padding".
     * @throws NullPointerException     if the key or any retrieved metadata is null.
     * @throws CertificateException     if there is an issue with the certificate chain.
     * @throws IOException              if there is an I/O error during the operation.
     * @throws NoSuchAlgorithmException if the requested algorithm is not available.
     * @throws InvalidKeySpecException  if the key specification is invalid.
     * @throws NoSuchProviderException  if the requested security provider is not available.
     * @throws KeyStoreException        if there is an error accessing the keystore or if the key type is unsupported.
     */
    private String buildTransformation(Key key) throws NullPointerException, CertificateException,
            IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, KeyStoreException {
        keyStore.load(null);
        KeyInfo keyInfo;
        String keyAlgorithm = key.getAlgorithm();
        String keyPadding;

        if (key instanceof SecretKey) {
            SecretKey secretKey = (SecretKey) key;
            SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKey.getAlgorithm(), ANDROID_KEY_STORE);
            keyInfo = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);
            keyPadding = keyInfo.getEncryptionPaddings()[0];
        } else if (key instanceof PrivateKey) {
            PrivateKey privateKey = (PrivateKey) key;
            KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), ANDROID_KEY_STORE);
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
            keyPadding = keyInfo.getSignaturePaddings()[0];
        } else {
            throw new KeyStoreException("Unsupported key type");
        }
        return keyAlgorithm + "/" + keyInfo.getBlockModes()[0] + "/" + keyPadding;
    }

    /**
     * Constructs the signature algorithm string based on the provided private key.
     * <p>
     * This method retrieves metadata from the given {@link PrivateKey} to dynamically construct
     * the signature algorithm string. It uses the {@link KeyFactory} to obtain the {@link KeyInfo}
     * of the private key, which includes details such as the digest algorithms supported by the key.
     * The method then combines the hash algorithm and the private key algorithm to form the signature
     * algorithm string.
     * </p>
     *
     * @param privateKey The {@link PrivateKey} for which the signature algorithm string is to be constructed.
     * @return A string representing the signature algorithm, which combines the hash algorithm and the key algorithm.
     * @throws NoSuchAlgorithmException If the algorithm of the private key is not available.
     * @throws NoSuchProviderException  If the specified provider is not available.
     * @throws InvalidKeySpecException  If the key specification is invalid or cannot be retrieved.
     */
    private String buildSignatureAlgorithm(PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm(), ANDROID_KEY_STORE);
        KeyInfo keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo.class);
        String hashAlgorithm = keyInfo.getDigests()[0].replaceAll("-", "");
        String algorithm = privateKey.getAlgorithm();
        if (algorithm.contains("EC")) {
            algorithm += "DSA";
        }
        return hashAlgorithm + "with" + algorithm;
    }

    /**
     * Prints detailed information about the currently loaded key.
     * <p>
     * This method retrieves and displays information about a key stored in the Android KeyStore.
     * It handles both {@link SecretKey} (symmetric keys) and {@link KeyPair} (asymmetric keys).
     * The information displayed includes the key ID, block modes, security level, origin, and purpose
     * for {@link SecretKey}. For {@link KeyPair}, it displays the key algorithm and format.
     * <p>
     * Note that this method should be used for testing or demonstration purposes and will be removed
     * in the release version.
     *
     * @throws NullPointerException      if the specified key does not exist.
     * @throws CertificateException      if there is an issue loading the certificate chain.
     * @throws IOException               if there is an I/O error during the operation.
     * @throws NoSuchAlgorithmException  if the requested algorithm is not available.
     * @throws InvalidKeySpecException   if the key specification is invalid.
     * @throws NoSuchProviderException   if the specified provider is not available.
     * @throws UnrecoverableKeyException if the key cannot be recovered from the keystore.
     * @throws KeyStoreException         if there is an error accessing the keystore.
     */ // TODO: DELETE BEFORE FINAL RELEASE
    public void showKeyInfo() throws NullPointerException, CertificateException, IOException,
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, UnrecoverableKeyException,
            KeyStoreException {
        keyStore.load(null);
        Key key = keyStore.getKey(KEY_NAME, null);
        KeyInfo keyInfo;

        if (key instanceof SecretKey) {
            SecretKey secretKey = (SecretKey) key;
            SecretKeyFactory factory = SecretKeyFactory.getInstance(secretKey.getAlgorithm(), ANDROID_KEY_STORE);
            keyInfo = (KeyInfo) factory.getKeySpec(secretKey, KeyInfo.class);
            System.out.println("Key algorithm: " + secretKey.getAlgorithm());
        } else if (key instanceof PrivateKey) {
            KeyPair keyPair = new KeyPair(keyStore.getCertificate(KEY_NAME).getPublicKey(), (PrivateKey) key);
            KeyFactory factory = KeyFactory.getInstance(keyPair.getPrivate().getAlgorithm(), ANDROID_KEY_STORE);
            keyInfo = factory.getKeySpec(keyPair.getPrivate(), KeyInfo.class);
            System.out.println("Key algorithm: " + keyPair.getPrivate().getAlgorithm());
        } else {
            throw new KeyStoreException("Unsupported key type");
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            System.out.println("KeyID: " + keyInfo.getKeystoreAlias() +
                    "\nKey padding: " + Arrays.toString(keyInfo.getEncryptionPaddings()) +
                    "\nKey size: " + keyInfo.getKeySize() +
                    "\nBlock modes: " + Arrays.toString(keyInfo.getBlockModes()) +
                    "\nSecurity-Level: " + keyInfo.getSecurityLevel() +
                    "\nOrigin: " + keyInfo.getOrigin() +
                    "\nPurpose: " + keyInfo.getPurposes());
        }
    }
}