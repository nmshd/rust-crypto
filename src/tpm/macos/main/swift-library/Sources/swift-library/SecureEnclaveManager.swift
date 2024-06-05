import Foundation
import LocalAuthentication
import Security
import CryptoKit
    
    /**
    Creates a new cryptographic key pair in the Secure Enclave.
     
    # Arguments
     
    * 'privateKeyName' - A String used to identify the private key.
     
    # Returns
     
    A 'SEKeyPair' containing the public and private keys on success, or a 'SecureEnclaveError' on failure.
    **/
    func create_key(keyID: String, algo: CFString, keySize: String ) throws -> SEKeyPair? {
        let accessControl = createAccessControlObject()
        
        let privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: keyID,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: accessControl,
        ]
        let params: [String: Any] = [
            // kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyType as String: algo, 
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyParams
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKeyReference = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
            throw SecureEnclaveError.CreateKeyError("A new public-private key pair could not be generated. \(String(describing: error))")
        }
        
        guard let publicKey = getPublicKeyFromPrivateKey(privateKey: privateKeyReference) else {
            throw SecureEnclaveError.CreateKeyError("Public key could not be received from the private key.")
        }
        
        let keyPair = SEKeyPair(publicKey: publicKey, privateKey: privateKeyReference)
        
        do{
            try storeKey_Keychain(keyID, privateKeyReference)
        }catch{
            // TODO: Programm stürzt ab
            SecureEnclaveError.CreateKeyError("The key could not be stored successfully into the keychain. \(String(describing: error))")
        }
        return keyPair
    }


    /** 
    Optimized method off @create_key() to communicate with the rust-side abstraction-layer.

    # Arguments

    * 'privateKeyName' - A 'RustString' data type used to identify the private key.

    # Returns

    A String representing the private and public key.
    **/
    func rustcall_create_key(key_id: RustString, key_algorithm_type: RustString) -> String {
        // For Secure Enclave is only ECC supported
        let ecc_algo = String(key_algorithm_type.toString().split(separator: ";")[0])
        let keySize = String(key_algorithm_type.toString().split(separator:";")[1])
        var algorithm: CFString;

        // Switch Case implement
        switch ecc_algo{
            case "kSecAttrKeyTypeECDSA": 
                algorithm = kSecAttrKeyTypeECDSA
            case "kSecAttrKeyTypeECSECPrimeRandom": 
                algorithm = kSecAttrKeyTypeECSECPrimeRandom
            default:
                return "\((SecureEnclaveError.CreateKeyError("Algorithm is not supported")))"
        }
        
        do{
            let keyPair = try create_key(keyID: key_id.toString(), algo: algorithm, keySize: keySize)
            return ("Private Key: "+String((keyPair?.privateKey.hashValue)!) + "\nPublic Key: " + String((keyPair?.publicKey.hashValue)!))
        }catch{
            return ("Error: \(String(describing: error))")
        }
    }
    
    
    /**
    Creates an access control object for a cryptographic operation.
     
    #Returns
     
    A 'SecAccessControl' configured for private key usage.
    **/
    func createAccessControlObject() -> SecAccessControl {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil)!
        return access
    }
    
    
    /**
    Encrypts data using a public key.
     
    # Arguments
     
    * 'data' - Data that has to be encrypted.
     
    * 'publicKey' - A SecKey data type representing a cryptographic public key.
     
    # Returns
     
    Data that has been encrypted on success, or a 'SecureEnclaveError' on failure.
    **/
    func encrypt_data(data: Data, publicKeyName: SecKey) throws -> Data {
        let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        var error: Unmanaged<CFError>?
        let result = SecKeyCreateEncryptedData(publicKeyName, algorithm, data as CFData, &error)
        
        if result == nil {
            throw SecureEnclaveError.EncryptionError("Data could not be encrypted. \(String(describing: error))")
        }
        
        return result! as Data
    }


    /** 
    Optimized method off @encrypt_data() to communicate with the rust-side abstraction-layer.

    # Arguments

    * 'data' - A 'RustString' data type used to represent the data that has to be encrypted as a String.

    * 'privateKeyName' - A 'RustString' data type used to identify the private key.

    # Returns

    A String representing the encrypted data.
    **/
    func rustcall_encrypt_data(key_id: RustString, data: RustString) -> String {
        do{
            let privateKey: SecKey = try load_key(key_id: key_id.toString())!
            let publicKey = getPublicKeyFromPrivateKey(privateKey: privateKey)
            let encryptedData: Data = try encrypt_data(data: data.toString().data(using: String.Encoding.utf8)!, publicKeyName: publicKey!)
            let encryptedData_string = encryptedData.base64EncodedString()
            return ("\(encryptedData_string)")
        }catch{
            return ("Error: \(String(describing: error))")
        }

    }
    
    
    /**
    Decrypts data using a private key.
     
    # Arguments
     
    * 'data' - Encrypted data that has to be decrypted.
     
    * 'privateKey' - A SecKey data type representing a cryptographic private key.
     
    # Returns
     
    Data that has been decrypted on success, or a 'SecureEnclaveError' on failure.
    **/
    func decrypt_data(data: Data, privateKey: SecKey) throws -> Data {
        let algorithm: SecKeyAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        var error: Unmanaged<CFError>?
        let result = SecKeyCreateDecryptedData(privateKey, algorithm, data as CFData, &error)
        
        if result == nil {
            throw SecureEnclaveError.DecryptionError("Data could not be decrypted. \(String(describing: error))")
        }
        
        return result! as Data
    }

    /** 
    Optimized method off @decrypt_data() to communicate with the rust-side abstraction-layer.

    # Arguments

    * 'data' - A 'RustString' data type used to represent the data that has to be decrypted as a String.

    * 'privateKeyName' - A 'RustString' data type used to identify the private key.

    # Returns

    A String representing the decrypted data.
    **/
    func rustcall_decrypt_data(key_id: RustString, data: RustString) -> String{
        do{
            guard let data = Data(base64Encoded: data.toString())
            else {
                return ("Invalid base64 input")
            }
                                    
            guard let decrypted_value = String(data: try decrypt_data(data: data, privateKey: load_key(key_id: key_id.toString())!), encoding: .utf8)
            else {
                return ("Converting decrypted data to string")
            }
            
            return ("\(decrypted_value)")
        } catch {
            return ("Error: \(String(describing: error))")
        }
    }
    
    
    
    /**
    Retrieves the public key associated with a given private key.
     
    # Arguments
     
    * 'privateKey' - A SecKey data type representing a cryptographic private key.
     
    # Returns
     
    Optionally a public key representing a cryptographic public key on success, or 'nil' on failure
     
    **/
    func getPublicKeyFromPrivateKey(privateKey: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(privateKey)
    }
    
    
    /**
    Signs data using a private key.
     
    # Arguments
     
    * 'privateKey' - A SecKey data type representing a cryptographic private key.
     
    * 'content' - A CFData data type of the Core Foundation that has to be signed.
     
    # Returns
     
    Optionally data that has been signed as a CFData data type on success, or 'nil' on failure.
    **/
    func sign_data(data: CFData, privateKeyReference: SecKey, algorithm: SecKeyAlgorithm) throws -> CFData? {
        let sign_algorithm = algorithm;
        if !SecKeyIsAlgorithmSupported(privateKeyReference, SecKeyOperationType.sign, sign_algorithm){
            throw SecureEnclaveError.SigningError("Algorithm is not supported")
        }
        
        var error: Unmanaged<CFError>?
        guard let signed_data = SecKeyCreateSignature(privateKeyReference, sign_algorithm, data as CFData, &error)
        else{
            throw SecureEnclaveError.SigningError("Data could not be signed: \(String(describing: error))")
        }
        return signed_data
    }
    

    /** 
    Optimized method off @sign_data() to communicate with the rust-side abstraction-layer.

    # Arguments

    * 'data' - A 'RustString' data type used to represent the data that has to be signed as a String.

    * 'privateKeyName' - A 'RustString' data type used to identify the private key.

    # Returns

    A String representing the signed data.
    **/
    func rustcall_sign_data(key_id: RustString, data: RustString, algo: RustString) -> String{
        let privateKeyName_string = key_id.toString()
        let data_cfdata = data.toString().data(using: String.Encoding.utf8)! as CFData

        do {
            let appple_algo_enum = try convert_sign_algo(algo: algo)
            let privateKeyReference = try load_key(key_id: privateKeyName_string)!
            let signed_data = try ((sign_data(data: data_cfdata, privateKeyReference: privateKeyReference, algorithm: appple_algo_enum))! as Data) 
            return signed_data.base64EncodedString(options: [])
        }catch{
            return "Error: \(String(describing: error))"
        }
    }
    
    
    /**
    Verifies a signature using a public key.
     
    # Arguments
     
    * 'publicKey - A SecKey data type representing a cryptographic public key.
     
    * 'content' - A String of the data that has to be verified.
     
    * 'signature' - A CFData data type of the Core Foundation that is the signature.
     
    # Returns
     
    A boolean if the signature is valid on success, or a 'SecureEnclaveError' on failure.
    **/
    func verify_signature(publicKey: SecKey, data: String, signature: String, algo: SecKeyAlgorithm) throws -> Bool {
        let sign_algorithm = algo
        guard Data(base64Encoded: signature) != nil else{
            throw SecureEnclaveError.SignatureVerificationError("Invalid message to verify")
        }
        
        guard let data_data = data.data(using: String.Encoding.utf8)
        else{
            throw SecureEnclaveError.SignatureVerificationError("Invalid message to verify")
        }
        
        var error: Unmanaged<CFError>?
        if SecKeyVerifySignature(publicKey, sign_algorithm, data_data as CFData, Data(base64Encoded: signature, options: [])! as CFData, &error){
            return true
        } else{
            return false
        }
    }


    /** 
    Optimized method off @verify_data() to communicate with the rust-side abstraction-layer.

    # Arguments

    * 'data' - A 'RustString' data type used to represent the data that has to be verified as a String.

    * 'signature' - A 'RustString' data type used to represent the signature of the signed data as a String.

    * 'publicKeyName' - A 'RustString' data type used to identify the public key.

    # Returns

    A String if the data could have been verified with the signature.
    **/
    func rustcall_verify_data(key_id: RustString, data: RustString, signature: RustString, algo: RustString) -> String {
        do{
            let publicKeyName_string = key_id.toString()
            let data_string = data.toString()
            let signature_string = signature.toString()
            let appple_algo_enum = try convert_sign_algo(algo: algo)

            guard let publicKey = getPublicKeyFromPrivateKey(privateKey: try load_key(key_id: publicKeyName_string)!)else{
                throw SecureEnclaveError.SignatureVerificationError("Public key could not be received from the private key")
            }
            let status = try verify_signature(publicKey: publicKey, data: data_string, signature: signature_string, algo: appple_algo_enum)
            
            if status == true{
                return "true"
            }else{
                return "false"
            }

        }catch{
            return "Error: \(String(describing: error))"
        }
    }
    
    
    // Represents errors that can occur within 'SecureEnclaveManager'.
    enum SecureEnclaveError: Error {
        case runtimeError(String)
        case SigningError(String)
        case DecryptionError(String)
        case EncryptionError(String)
        case SignatureVerificationError(String)
        case InitializationError(String)
        case CreateKeyError(String)
        case LoadKeyError(String)
    }
    
    // Represents a pair of cryptographic keys.
    struct SEKeyPair {
        let publicKey: SecKey
        let privateKey: SecKey
    }
    
    
    /**
    Loads a cryptographic private key from the keychain.
     
    # Arguments
     
    * 'key_id' - A String used as the identifier for the key
     
    # Returns
     
    Optionally the key as a SecKey data type on success, or a 'SecureEnclaveError' on failure.
    **/
    func load_key(key_id: String) throws -> SecKey? {
        let tag = key_id
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String             : true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw SecureEnclaveError.LoadKeyError("Key could not be found.")
        }
        return (item as! SecKey)
    }


    /** 
    Optimized method off @load_key() to communicate with the rust-side abstraction-layer.

    # Arguments

    * 'keyID' - A 'RustString' data type used to represent identifier for the key as a String.

    # Returns

    A String representing the private key as a String.
    **/
    func rustcall_load_key(keyID: RustString) -> String {
        do {
            guard let key = try load_key(key_id: keyID.toString()) else {
                return "Key not found."
            }
            return "\(key.hashValue)"
        } catch {
            return "Error: \(String(describing: error))"
        }
    }
    
    
    /**
    Stores a cryptographic key in the keychain.
     
    # Arguments
     
    * 'name' - A String used to identify the key in the keychain.
     
    * 'privateKey' - A SecKey data type representing a cryptographic private key.
     
    # Returns
     
    A 'SecureEnclaveError' on failure.
    **/
    func storeKey_Keychain(_ name: String, _ privateKey: SecKey) throws {
        let key = privateKey
        let tag = name.data(using: .utf8)!
        let addquery: [String: Any] = [kSecClass as String: kSecClassKey,
                                       kSecAttrApplicationTag as String: tag,
                                       kSecValueRef as String: key]
        
        let status = SecItemAdd(addquery as CFDictionary, nil)
        guard status == errSecSuccess
        else {
            throw SecureEnclaveError.CreateKeyError("Failed to store Key in the Keychain.")
        }
    }
    
    // static var isAvailable: Bool {
    //     return true
    // }
    
    /**
    Inizializes a module by creating a private key and the associated private key. Optimized to communicate with the rust-side abstraction-layer.
     
    # Returns
     
    A boolean if the module has been inizializes correctly on success, or a 'SecureEnclaveError' on failure.
    **/
    func initializeModule() -> Bool  {
        if #available(macOS 10.15, *) {
            var initialized: Bool = true
            //Warnings
            // var privateKey: P256.KeyAgreement.PrivateKey?
            // var publicKey: P256.KeyAgreement.PublicKey?
            do{
                guard initialized else{
                    throw SecureEnclaveError.InitializationError("Error: Did not initailze any module")
                }
                guard SecureEnclave.isAvailable else {
                    throw SecureEnclaveError.InitializationError("Error: Secure Enclave is not available on this device")
                }  
            }catch{
                return false
            }
        } else {
            return true
        }

        return true
    }

    func convert_sign_algo(algo: RustString) throws -> SecKeyAlgorithm{
        let algo = algo.toString().split(separator: ";")
        let appple_algo_enum: SecKeyAlgorithm; 
        
        switch algo[1] {
            case "SHA1": 
                appple_algo_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA1
            case "SHA224": 
                appple_algo_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
            case "SHA256": 
                appple_algo_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            case "SHA384":
                appple_algo_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
            case "SHA512": 
                appple_algo_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512
            default: 
                throw SecureEnclaveError.SigningError("Algorithm is not supported")
        }

        return appple_algo_enum
    }

    func convert_encrypt_algo(algo: RustString) throws -> SecKeyAlgorithm{
        let algo = algo.toString().split(separator: ";")
        let appple_algo_enum: SecKeyAlgorithm; 
        
        switch algo[1] {
            case "SHA1": 
                appple_algo_enum = SecKeyAlgorithm.eciesEncryptionStandardX963SHA1AESGCM
            case "SHA224": 
                appple_algo_enum = SecKeyAlgorithm.eciesEncryptionStandardX963SHA224AESGCM
            case "SHA256": 
                appple_algo_enum = SecKeyAlgorithm.eciesEncryptionStandardX963SHA256AESGCM
            case "SHA384":
                appple_algo_enum = SecKeyAlgorithm.eciesEncryptionStandardX963SHA384AESGCM
            case "SHA512": 
                appple_algo_enum = SecKeyAlgorithm.eciesEncryptionStandardX963SHA512AESGCM
            default: 
                throw SecureEnclaveError.EncryptionError("Algorithm is not supported")
        }

        return appple_algo_enum
    }
