import Foundation
import LocalAuthentication
import Security
import CryptoKit
    
    /**
    Creates a new cryptographic key pair in the Secure Enclave.
    
    - Parameter keyID: A String used to identify the private key.
    - Parameter algorithm: A 'CFString' data type representing the algorithm used to create the key pair.
    - Parameter keySize: A String representing the size of the key.
    - Throws: 'SecureEnclaveError.CreateKeyError' if a new public-private key pair could not be generated.
    - Returns: A 'SEKeyPair' containing the public and private key on success, or a 'SecureEnclaveError' on failure.
    */
    func create_key(key_id: String, algorithm: CFString, key_size: String ) throws -> SEKeyPair? {
        let accessControl = create_access_control_object()
        let params: [String: Any]; 
        if algorithm == kSecAttrKeyTypeRSA{ // Asymmetric Encryption
            params =
                [kSecAttrKeyType as String:           algorithm,
                kSecAttrKeySizeInBits as String:      key_size,
                kSecPrivateKeyAttrs as String:        [
                    kSecAttrIsPermanent as String:    false,
                    kSecAttrApplicationTag as String: key_id,
                    kSecAttrAccessControl as String: accessControl,
                ]
            ]
        }else{
            let privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: key_id,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
            ]
            params = [
                kSecAttrKeyType as String: algorithm,
                kSecAttrKeySizeInBits as String: key_size,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: privateKeyParams
            ]
        }
        
        var error: Unmanaged<CFError>?
        guard let privateKeyReference = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
            throw SecureEnclaveError.CreateKeyError("A new public-private key pair could not be generated. \(String(describing: error))")
        }
        
        guard let publicKey = get_public_key_from_private_key(private_key: privateKeyReference) else {
            throw SecureEnclaveError.CreateKeyError("Public key could not be received from the private key. \(String(describing: error))")
        }
        
        let keyPair = SEKeyPair(publicKey: publicKey, privateKey: privateKeyReference)
        
        do{
            try storeKey_Keychain(key_id, privateKeyReference)
        }catch{
            // TODO: Program is crashing
            throw SecureEnclaveError.CreateKeyError("The key could not be stored successfully into the keychain. \(String(describing: error))")
        }
        return keyPair
    }


    /** 
    Optimized method of @create_key() to communicate with the rust-side abstraction-layer.

    - Parameter key_id: A 'RustString' data type used to identify the private key.
    - Parameter key_type - A 'RustString' data type used to represent the algorithm that is used to create the key pair.
    - Returns: A String representing the private and public key, or an error as a String on failure.
    */
    func rustcall_create_key(key_id: RustString, key_type: RustString) -> String {
        // For Secure Enclave is only ECC supported
        let algorithm = String(key_type.toString().split(separator: ";")[0])
        let keySize = String(key_type.toString().split(separator:";")[1])
        do{
            let algorithm = try get_key_type(key_type: algorithm);
            let keyPair = try create_key(key_id: key_id.toString(), algorithm: algorithm, key_size: keySize)
            return ("Private Key: "+String((keyPair?.privateKey.hashValue)!) + "\nPublic Key: " + String((keyPair?.publicKey.hashValue)!))
        }catch{
            return ("Error: \(String(describing: error))")
        }
    }
    
    
    /**
    Creates an access control object for a cryptographic operation.
     
    - Returns: A 'SecAccessControl' configured for private key usage.
    */
    func create_access_control_object() -> SecAccessControl {
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly, 
                .privateKeyUsage, 
                nil)!
            
            return access
    }
    
    
    /**
    Encrypts data using a public key.

    - Parameter data: Data that has to be encrypted.
    - Parameter publicKeyName: A 'SecKey' data type representing a cryptographic public key.
    - Parameter algorithm: A 'SecKeyAlgorithm' data type representing the algorithm used to encrypt the data.
    - Throws: 'SecureEnclaveError.EncryptionError' if the data could not be encrypted.
    - Returns: Data that has been encrypted.
    */
    func encrypt_data(data: Data, public_key_name: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        let algorithm = algorithm
        var error: Unmanaged<CFError>?
        let result = SecKeyCreateEncryptedData(public_key_name, algorithm, data as CFData, &error)
        
        if result == nil {
            throw SecureEnclaveError.EncryptionError("Data could not be encrypted. \(String(describing: error))")
        }
        
        return result! as Data
    }


    /** 
    Optimized method of @encrypt_data() to communicate with the rust-side abstraction-layer.

    - Parameter key_id: A 'RustString' data type used to identify the private key.
    - Parameter data: A 'RustString' data type used to represent the data that has to be encrypted as a String.
    - Parameter algorithm: A 'RustString' data type used to represent the algorithm that is used to encrypt the data.
    - Parameter hash: A 'RustString' data type used to represent the hash that is used.
    - Returns: A String representing the encrypted data, or an error as a String on failure.
    */
    func rustcall_encrypt_data(key_id: RustString, data: RustString, algorithm: RustString, hash: RustString) -> (Bool, String) {
        do{
            let key_type = try get_key_type(key_type: algorithm.toString())
            let privateKey: SecKey = try load_key(key_id: key_id.toString(), algorithm: key_type)!
            let publicKey = get_public_key_from_private_key(private_key: privateKey)
            let algorithm = try get_encrypt_algorithm(algorithm: algorithm.toString(), hash: hash.toString()); 
            let encryptedData: Data = try encrypt_data(data: data.toString().data(using: String.Encoding.utf8)!, public_key_name: publicKey!, algorithm: algorithm)
            let encryptedData_string = encryptedData.base64EncodedString()
            return (false, "\(encryptedData_string)")
        }catch{
            return (true, "Error: \(String(describing: error))")
        }

    }
    
    
    /**
    Decrypts data using a private key.

    - Parameter data: Encrypted data that has to be decrypted.
    - Parameter privateKey: A 'SecKey' data type representing a cryptographic private key.
    - Parameter algorithm: A 'SecKeyAlgorithm' data type representing the algorithm used to decrypt the data.
    - Throws: 'SecureEnclaveError.DecryptionError' if the data could not be decrypted.
    - Returns: Data that has been decrypted.
    */
    func decrypt_data(data: Data, private_key: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        let algorithm: SecKeyAlgorithm = algorithm
        var error: Unmanaged<CFError>?
        let result = SecKeyCreateDecryptedData(private_key, algorithm, data as CFData, &error)
        if result == nil {
            throw SecureEnclaveError.DecryptionError("Data could not be decrypted. \(String(describing: error))")
        }
        return result! as Data
    }

    /** 
    Optimized method of @decrypt_data() to communicate with the rust-side abstraction-layer.

    - Parameter key_id: A 'RustString' data type used to identify the private key.
    - Parameter data: A 'RustString' data type used to represent the data that has to be decrypted as a String.
    - Parameter algorithm: A 'RustString' data type used to represent the algorithm that is used to decrypt the data.
    - Parameter hash: A 'RustString' data type used to represent the hash that is used.
    - Returns: A String representing the decrypted data, or an error as a String on failure.
    */
    func rustcall_decrypt_data(key_id: RustString, data: RustString, algorithm: RustString, hash: RustString) -> (Bool, String) {
        do{
            let seckey_algorithm_enum = try get_encrypt_algorithm(algorithm: algorithm.toString(), hash: hash.toString())
            let key_type = try get_key_type(key_type: algorithm.toString())
            guard let data = Data(base64Encoded: data.toString())
            else {
                return (true, "Invalid base64 input") 
            }
                                    
            guard let decrypted_value = String(data: try decrypt_data(data: data, private_key: load_key(key_id: key_id.toString(), algorithm: key_type)!, algorithm: seckey_algorithm_enum), encoding: .utf8) else {
                return (true, "Converting decrypted data to string")
            }
            
            return (false, "\(decrypted_value)")
        } catch {
            return (true, "Error: \(String(describing: error))")
        }
    }
    
    
    
    /**
    Retrieves the public key associated with a given private key.

    - Parameter privateKey: A 'SecKey' data type representing a cryptographic private key.
    - Returns: Optionally a public key representing a cryptographic public key on success, or 'nil' on failure.
    */
    func get_public_key_from_private_key(private_key: SecKey) -> SecKey? {
        return SecKeyCopyPublicKey(private_key)
    }
    
    
    /**
    Signs data using a private key.

    - Parameter data: Data that has to be signed.
    - Parameter privateKeyReference: A 'SecKey' data type representing a cryptographic private key.
    - Parameter algorithm: A 'SecKeyAlgorithm' data type representing the algorithm used to sign the data.
    - Throws: 'SecureEnclaveError.SigningError' if the data could not be signed.
    - Returns: Optionally data that has been signed as a CFData data type on success, or 'nil' on failure.
    */
    func sign_data(data: CFData, privateKeyReference: SecKey, algorithm: SecKeyAlgorithm) throws -> CFData? {
        let sign_algorithm = algorithm;
        if !SecKeyIsAlgorithmSupported(privateKeyReference, SecKeyOperationType.sign, sign_algorithm){
            throw SecureEnclaveError.SigningError("Algorithm is not supported.)")
        }
        
        var error: Unmanaged<CFError>?
        guard let signed_data = SecKeyCreateSignature(privateKeyReference, sign_algorithm, data as CFData, &error)
        else{
            throw SecureEnclaveError.SigningError("Data could not be signed: \(String(describing: error))")
        }
        return signed_data
    }
    

    /** 
    Optimized method of @sign_data() to communicate with the rust-side abstraction-layer.

    - Parameter key_id: A 'RustString' data type used to identify the private key.
    - Parameter data: A 'RustString' data type used to represent the data that has to be signed as a String.
    - Parameter algorithm: A 'RustString' data type used to represent the algorithm that is used to sign the data.
    - Parameter hash: A 'RustString' data type used to represent the hash that is used.
    - Returns: A String representing the signed data, or an error as a String on failure.
    */
    func rustcall_sign_data(key_id: RustString, data: RustString, algorithm: RustString, hash: RustString) -> (Bool, String){
        let privateKeyName_string = key_id.toString()
        let data_cfdata = data.toString().data(using: String.Encoding.utf8)! as CFData

        do {
            let seckey_algorithm_enum = try get_sign_algorithm(algorithm: algorithm.toString(), hash: hash.toString())
            let key_type = try get_key_type(key_type: algorithm.toString()) as CFString
            let privateKeyReference = try load_key(key_id: privateKeyName_string, algorithm: key_type)!
            let signed_data = try ((sign_data(data: data_cfdata, privateKeyReference: privateKeyReference, algorithm: seckey_algorithm_enum))! as Data) 
            return (false, signed_data.base64EncodedString(options: []))
        }catch{
            return (true, "Error:  \(String(describing: error))")
        }
    }
    
    
    /**
    Verifies a signature using a public key.

    - Parameter publicKey: A 'SecKey' data type representing a cryptographic public key.
    - Parameter data: A String of the sata that has to be verified.
    - Parameter signature: A String of the signature that has to be verified.
    - Parameter sign_algorithm: A 'SecKeyAlgorithm' data type representing the algorithm used to verify the signature.
    - Throws: 'SecureEnclaveError.SignatureVerificationError' if the signature could not be verified.
    - Returns: A boolean if the signature is valid ('true') or not ('false').
    */
    func verify_signature(public_key: SecKey, data: String, signature: String, sign_algorithm: SecKeyAlgorithm) throws -> Bool {
        let sign_algorithm = sign_algorithm
        guard Data(base64Encoded: signature) != nil else{
            throw SecureEnclaveError.SignatureVerificationError("Invalid message to verify.)")
        }
        
        guard let data_data = data.data(using: String.Encoding.utf8)
        else{
            throw SecureEnclaveError.SignatureVerificationError("Invalid message to verify.)")
        }
        
        var error: Unmanaged<CFError>?
        if SecKeyVerifySignature(public_key, sign_algorithm, data_data as CFData, Data(base64Encoded: signature, options: [])! as CFData, &error){
            return true
        } else{
            return false
        }
    }


    /** 
    Optimized method of @verify_data() to communicate with the rust-side abstraction-layer.

    - Parameter key_id: A 'RustString' data type used to identify the public key.
    - Parameter data: A 'RustString' data type used to represent the data that has to be verified with the signature as a String.
    - Parameter signature: A 'RustString' data type used to represent the signature of the signed data as a String.
    - Parameter algorithm: A 'RustString' data type used to represent the algorithm that is used to verify the signature.
    - Parameter hash: A 'RustString' data type used to represent the hash that is used.
    - Returns: A String if the data could have been verified with the signature, or an error as a String on failure.
    */
    func rustcall_verify_data(key_id: RustString, data: RustString, signature: RustString, algorithm: RustString, hash: RustString) -> String {
        do{
            //Convert Datatype from RustString to String 
            let publicKeyName_string = key_id.toString()
            let data_string = data.toString()
            let signature_string = signature.toString()

            //Get Algorithm enums
            let seckey_algorithm_enum = try get_sign_algorithm(algorithm: algorithm.toString(), hash: hash.toString())
            let key_type = try get_key_type(key_type: algorithm.toString())

            guard let publicKey = get_public_key_from_private_key(private_key: try load_key(key_id: publicKeyName_string, algorithm: key_type)!)else{
                throw SecureEnclaveError.SignatureVerificationError("Public key could not be received from the private key.)")
            }
            let status = try verify_signature(public_key: publicKey, data: data_string, signature: signature_string, sign_algorithm: seckey_algorithm_enum)
            
            if status == true{
                return "true"
            }else{
                return "false"
            }
        }catch{
            return "Error: \(String(describing: error))"
        }
    }
    
    
    /// Represents errors that can occur within 'SecureEnclaveManager'.
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
    
    /// Represents a pair of cryptographic keys, both the public key and the private key are objects of the data type 'SecKey'.
    struct SEKeyPair {
        let publicKey: SecKey
        let privateKey: SecKey
    }
    
    
    /**
    Loads a cryptographic private key from the keychain.

    - Parameter key_id: A String used as the identifier for the key.
    - Parameter algo: A 'CFString' data type representing the algorithm used to create the key pair.
    - Throws: 'SecureEnclaveError.LoadKeyError' if the key could not be found.
    - Returns: Optionally the key as a SecKey data type on success, or a nil on failure.
    */
    func load_key(key_id: String, algorithm: CFString) throws -> SecKey? {
        let tag = key_id
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : algorithm,
            kSecReturnRef as String             : true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw SecureEnclaveError.LoadKeyError("Key could not be found.)")
        }
        return (item as! SecKey)
    }


    /** 
    Optimized method of @load_key() to communicate with the rust-side abstraction-layer.

    - Parameter key_id: A 'RustString' data type used to identify the private key.
    - Parameter key_type - A 'RustString' data type used to represent the algorithm that is used to create the key pair.
    - Parameter hash - A 'RustString' data type used to represent the hash that is used.
    - Returns: A String representing the private key, or an error as a String on failure.
    */
    func rustcall_load_key(key_id: RustString, key_type: RustString, hash: RustString) -> String {
        do {
            let key_algorithm = try get_key_type(key_type: key_type.toString())
            let operation_algorithm_encryption = try get_encrypt_algorithm(algorithm: key_type.toString(), hash: hash.toString())
            let operation_algorithm_signing = try get_sign_algorithm(algorithm: key_type.toString(), hash: hash.toString())

            guard let key = try load_key(key_id: key_id.toString(), algorithm: key_algorithm) else {
                return "Key with KeyID \(key_id) could not be found."
            }

            try check_algorithm_support(key: get_public_key_from_private_key(private_key: key)!, operation: SecKeyOperationType.encrypt, algorithm: operation_algorithm_encryption)
            try check_algorithm_support(key: key, operation: SecKeyOperationType.decrypt, algorithm: operation_algorithm_encryption)
            try check_algorithm_support(key: key, operation: SecKeyOperationType.sign, algorithm: operation_algorithm_signing)
            try check_algorithm_support(key: get_public_key_from_private_key(private_key: key)!, operation: SecKeyOperationType.verify, algorithm: operation_algorithm_signing)
            
            return "\(key.hashValue)"
        } catch {
            return "Error: \(key_type.toString()) + \(String(describing: error))"
        }
    }
    
    
    /**
    Stores a cryptographic key in the keychain.

    - Parameter name: A String used to identify the key in the keychain.
    - Parameter privateKey: A 'SecKey' data type representing a cryptographic private key.
    - Throws: 'SecureEnclaveError.CreateKeyError' if the key could not be stored.
    */
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
    
    /**
    Initializes a module by creating a private key and the associated private key. 
    Optimized to communicate with the rust-side abstraction-layer.
     
    - Returns: A boolean if the module has been inizializes correctly on success ('true') or not ('false'), or a 'SecureEnclaveError' on failure.
    */
    func initialize_module() -> Bool  {
        if #available(macOS 10.15, *) {
            do{
                guard SecureEnclave.isAvailable else {
                    throw SecureEnclaveError.runtimeError("Secure Enclave is unavailable on this device. ")
                }
                return true
            }catch{
                return false
            }
        } else {
            return true
        }
    }

    /**
    Checks if the algorithm is supported.

    - Parameter key: A 'SecKey' data type representing a cryptographic key.
    */
    func check_algorithm_support(key: SecKey, operation: SecKeyOperationType, algorithm: SecKeyAlgorithm) throws {
        var operation_string: String; 
        switch operation{
            case SecKeyOperationType.encrypt: 
                operation_string = "encrypt"
            case SecKeyOperationType.decrypt: 
                operation_string = "decrypt"
            case SecKeyOperationType.sign: 
                operation_string = "sign"
            case SecKeyOperationType.verify: 
                operation_string = "verify"
            default: 
                operation_string = "Noting"
        }
        //Key usage is going to be implemented. 
        if !SecKeyIsAlgorithmSupported(key, operation, algorithm){
            throw SecureEnclaveError.EncryptionError("Given Keytype and algorithm do not support the \(operation_string) operation. Please choose other keytype or algorithm.")
        } 
    }


    /**
    Retrieves the type of the key, representing which algorithm is used.

    - Parameter key_type: A String representing the algorithm used to create the key pair.
    - Throws: 'SecureEnclaveError.CreateKeyError' if the key algorithm is not supported.
    - Returns: A 'CFString' representing the algorithm used to create the key pair.
    */
    func get_key_type(key_type: String) throws -> CFString {
        switch key_type{
            case "RSA": 
                return kSecAttrKeyTypeRSA
            // According documentation of Apple, kSecAttrKeyTypeECDSA is deprecated. Suggesting to use kSecAttrKeyTypeECSECPrimeRandom instead.
            case "ECDSA": 
                return kSecAttrKeyTypeECSECPrimeRandom 
            default:
                throw SecureEnclaveError.CreateKeyError("Key Algorithm is not supported.)")
        }
    }


    /**
    Retrieves the algorithm used for signing and verifying.

    - Parameter algorithm: A String representing the algorithm.
    - Parameter hash: A String representing the hash that is used.
    - Throws: 'SecureEnclaveError.SigningError' if the hash for signing is not supported.
    - Returns: A 'SecKeyAlgorithm' representing the algorithm used for signing and verifying.
    */
    func get_sign_algorithm(algorithm: String, hash: String) throws -> SecKeyAlgorithm{
        let apple_algorithm_enum: SecKeyAlgorithm;
        if algorithm == "RSA"{
            switch hash {
                case "SHA224": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA224
                case "SHA256": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
                case "SHA384":
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
                default: 
                    throw SecureEnclaveError.SigningError("Hash for asymmetric signing with RSA is not supported.)")
            }
            return apple_algorithm_enum
        }else if algorithm == "ECDSA"{
            switch hash {
                case "SHA224": 
                    apple_algorithm_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA224
                case "SHA256": 
                    apple_algorithm_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
                case "SHA384":
                    apple_algorithm_enum = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA384
                default: 
                    throw SecureEnclaveError.SigningError("Hash for asymmetric signing with ECDSA is not supported.)")
            }
            return apple_algorithm_enum
        }
        else{
            throw SecureEnclaveError.SigningError("Algorithm for Encryption/Decryption not supported. Only RSA or ECDSA)")
        }
    }


    /**
    Retrieves the algorithm used for encryption and decryption.

    - Parameter algorithm: A String representing the algorithm.
    - Parameter hash: A String representing the hash that is used.
    - Throws: 'SecureEnclaveError.EncryptionError' if the hash for encryption is not supported.
    - Returns: A 'SecKeyAlgorithm' representing the algorithm used for encryption and decryption.
    */
    func get_encrypt_algorithm(algorithm: String, hash: String) throws -> SecKeyAlgorithm{
        let apple_algorithm_enum: SecKeyAlgorithm;

        if algorithm == "RSA"{
            switch hash {
                case "SHA1": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaEncryptionOAEPSHA1
                case "SHA224": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaEncryptionOAEPSHA224
                case "SHA256": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
                case "SHA384":
                    apple_algorithm_enum = SecKeyAlgorithm.rsaEncryptionOAEPSHA384
                default: 
                    throw SecureEnclaveError.EncryptionError("Hash for Encryption/Decryption is not supported.)")
            }
            return apple_algorithm_enum
        }else{
            throw SecureEnclaveError.EncryptionError("Algorithm for Encryption/Decryption not supported.))")
        }
    }
