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
    func create_key(keyID: String, algorithm: CFString, keySize: String ) throws -> SEKeyPair? {
        let accessControl = createAccessControlObject()
        let params: [String: Any]; 
        if algorithm == kSecAttrKeyTypeRSA{ // Asymmetric Encryption
            params =
                [kSecAttrKeyType as String:           algorithm,
                kSecAttrKeySizeInBits as String:      keySize,
                kSecPrivateKeyAttrs as String:        [
                    kSecAttrIsPermanent as String:    false,
                    kSecAttrApplicationTag as String: keyID,
                    kSecAttrAccessControl as String: accessControl,
                ]
            ]
        }else{ // Symmetric + Asymmetric Encryption running on the Secure Enclave
            let privateKeyParams: [String: Any] = [
                kSecAttrLabel as String: keyID,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
            ]
            params = [
                kSecAttrKeyType as String: algorithm,
                kSecAttrKeySizeInBits as String: keySize,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: privateKeyParams
            ]
        }
        
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
            throw SecureEnclaveError.CreateKeyError("The key could not be stored successfully into the keychain. \(String(describing: error))")
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
    func rustcall_create_key(key_id: RustString, key_type: RustString) -> String {
        // For Secure Enclave is only ECC supported
        let algo = String(key_type.toString().split(separator: ";")[0])
        let keySize = String(key_type.toString().split(separator:";")[1])
        do{
            let algorithm = try get_key_type(key_type: algo);
            let keyPair = try create_key(keyID: key_id.toString(), algorithm: algorithm, keySize: keySize)
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
        if #available(macOS 10.13.4, *) {
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly, 
                .biometryAny,
                nil)!
            
            return access
        } else {
            let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly, 
                .privateKeyUsage, 
                nil)!
            
            return access
        }
    }
    
    
    /**
    Encrypts data using a public key.
     
    # Arguments
     
    * 'data' - Data that has to be encrypted.
     
    * 'publicKey' - A SecKey data type representing a cryptographic public key.
     
    # Returns
     
    Data that has been encrypted on success, or a 'SecureEnclaveError' on failure.
    **/
    func encrypt_data(data: Data, publicKeyName: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        let algorithm = algorithm
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
    func rustcall_encrypt_data(key_id: RustString, data: RustString, algorithm: RustString, hash: RustString) -> String {
        do{
            let key_type = try get_key_type(key_type: algorithm.toString())
            let privateKey: SecKey = try load_key(key_id: key_id.toString(), algo: key_type)!
            let publicKey = getPublicKeyFromPrivateKey(privateKey: privateKey)
            let algorithm = try get_encrypt_algorithm(algorithm: algorithm.toString(), hash: hash.toString()); 
            let encryptedData: Data = try encrypt_data(data: data.toString().data(using: String.Encoding.utf8)!, publicKeyName: publicKey!, algorithm: algorithm)
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
    func decrypt_data(data: Data, privateKey: SecKey, algorithm: SecKeyAlgorithm) throws -> Data {
        let algorithm: SecKeyAlgorithm = algorithm
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
    func rustcall_decrypt_data(key_id: RustString, data: RustString, algorithm: RustString, hash: RustString) -> String{
        do{
            let seckey_algorithm_enum = try get_encrypt_algorithm(algorithm: algorithm.toString(), hash: hash.toString())
            let key_type = try get_key_type(key_type: algorithm.toString())
            guard let data = Data(base64Encoded: data.toString())
            else {
                return ("Invalid base64 input") 
            }
                                    
            guard let decrypted_value = String(data: try decrypt_data(data: data, privateKey: load_key(key_id: key_id.toString(), algo: key_type)!, algorithm: seckey_algorithm_enum), encoding: .utf8) else {
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
    func rustcall_sign_data(key_id: RustString, data: RustString, algorithm: RustString, hash: RustString) -> String{
        let privateKeyName_string = key_id.toString()
        let data_cfdata = data.toString().data(using: String.Encoding.utf8)! as CFData

        do {
            let seckey_algorithm_enum = try get_sign_algorithm(algorithm: algorithm.toString(), hash: hash.toString())
            let key_type = try get_key_type(key_type: algorithm.toString()) as CFString
            let privateKeyReference = try load_key(key_id: privateKeyName_string, algo: key_type)!
            let signed_data = try ((sign_data(data: data_cfdata, privateKeyReference: privateKeyReference, algorithm: seckey_algorithm_enum))! as Data) 
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
    func verify_signature(publicKey: SecKey, data: String, signature: String, sign_algorithm: SecKeyAlgorithm) throws -> Bool {
        let sign_algorithm = sign_algorithm
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
    func rustcall_verify_data(key_id: RustString, data: RustString, signature: RustString, algorithm: RustString, hash: RustString) -> String {
        do{
            //Convert Datatype from RustString to String 
            let publicKeyName_string = key_id.toString()
            let data_string = data.toString()
            let signature_string = signature.toString()

            //Get Algorithm enums
            let seckey_algorithm_enum = try get_sign_algorithm(algorithm: algorithm.toString(), hash: hash.toString())
            let key_type = try get_key_type(key_type: algorithm.toString())

            guard let publicKey = getPublicKeyFromPrivateKey(privateKey: try load_key(key_id: publicKeyName_string, algo: key_type)!)else{
                throw SecureEnclaveError.SignatureVerificationError("Public key could not be received from the private key")
            }
            let status = try verify_signature(publicKey: publicKey, data: data_string, signature: signature_string, sign_algorithm: seckey_algorithm_enum)
            
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
    func load_key(key_id: String, algo: CFString) throws -> SecKey? {
        let tag = key_id
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : algo,
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
    func rustcall_load_key(key_id: RustString, key_type: RustString, hash: RustString) -> String {
        do {
            let key_algorithm = try get_key_type(key_type: key_type.toString())
            let operation_algorithm_encryption = try get_encrypt_algorithm(algorithm: key_type.toString(), hash: hash.toString())
            let operation_algorithm_signing = try get_sign_algorithm(algorithm: key_type.toString(), hash: hash.toString())

            guard let key = try load_key(key_id: key_id.toString(), algo: key_algorithm) else {
                return "Key with KeyID \(key_id) could not be found."
            }

            try check_algorithm_support(key: getPublicKeyFromPrivateKey(privateKey: key)!, operation: SecKeyOperationType.encrypt, algorithm: operation_algorithm_encryption)
            try check_algorithm_support(key: key, operation: SecKeyOperationType.decrypt, algorithm: operation_algorithm_encryption)
            try check_algorithm_support(key: key, operation: SecKeyOperationType.sign, algorithm: operation_algorithm_signing)
            try check_algorithm_support(key: getPublicKeyFromPrivateKey(privateKey: key)!, operation: SecKeyOperationType.verify, algorithm: operation_algorithm_signing)
            
            return "\(key.hashValue)"
        } catch {
            return "Error: \(key_type.toString()) + \(String(describing: error))"
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
    
    /**
    Inizializes a module by creating a private key and the associated private key. Optimized to communicate with the rust-side abstraction-layer.
     
    # Returns
     
    A boolean if the module has been inizializes correctly on success, or a 'SecureEnclaveError' on failure.
    **/
    func initialize_module() -> Bool  {
        if #available(macOS 10.15, *) {
            //Debug TODO
            // print("MacOS 10.15 and higher")
            do{
                guard SecureEnclave.isAvailable else {
                    throw SecureEnclaveError.runtimeError("Secure Enclave is unavailable on this device")
                }
                return true
            }catch{
                return false
            }
        } else {
            //Debug TODO
            // print("Not MacOS 10.15")
            return true
        }
    }

    func check_algorithm_support(key: SecKey, operation: SecKeyOperationType, algorithm: SecKeyAlgorithm) throws {
        var operation_string: String; 
        switch operation{
            case SecKeyOperationType.encrypt: 
                operation_string = "encrypt"
            default: 
                operation_string = "Noting"
        }
        //Key usage is going to be implemented. 
        if !SecKeyIsAlgorithmSupported(key, operation, algorithm){
            throw SecureEnclaveError.EncryptionError("Given Keytype and algorithm do not support the \(operation_string) operation. Please choose other keytype or algorithm.")
        } 
    }

    func get_key_type(key_type: String) throws -> CFString {
        switch key_type{
            case "RSA": 
                return kSecAttrKeyTypeRSA
            default:
                throw SecureEnclaveError.CreateKeyError("Key Algorithm is not supported")
        }
    }

    func get_sign_algorithm(algorithm: String, hash: String) throws -> SecKeyAlgorithm{
        let apple_algorithm_enum: SecKeyAlgorithm;
        if algorithm == "RSA"{
            switch hash {
                case "SHA1": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA1
                case "SHA224": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA224
                case "SHA256": 
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA256
                case "SHA384":
                    apple_algorithm_enum = SecKeyAlgorithm.rsaSignatureMessagePSSSHA384
                default: 
                    throw SecureEnclaveError.SigningError("Hash for Signing is not supported")
            }
            return apple_algorithm_enum
        }else{
            throw SecureEnclaveError.EncryptionError("Algorithm for Encrypt / Decrypt not supported")
        }
    }

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
                    throw SecureEnclaveError.EncryptionError("Hash for Encryption / Decryption is not supported")
            }
            return apple_algorithm_enum
        }else{
            throw SecureEnclaveError.EncryptionError("Algorithm for Encrypt / Decrypt not supported")
        }
    }
