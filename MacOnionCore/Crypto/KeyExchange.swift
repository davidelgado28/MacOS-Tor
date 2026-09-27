import Foundation
import CryptoKit

public struct KeyExchange {
    public static func deriveSharedKey(
        peerPublicKeyBase64: String
    ) throws -> (ephemeralPublicKeyData: Data, symmetricKey: SymmetricKey) {
        guard let peerKeyData = Data(base64Encoded: peerPublicKeyBase64),
              let peerPublicKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerKeyData) else {
            throw KeyExchangeError.invalidPublicKey
        }
        let clientEphemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let clientEphemeralPublicKeyData = clientEphemeralPrivateKey.publicKey.rawRepresentation
        let sharedSecret = try clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("MacOnionHKDFSalt".utf8),
            sharedInfo: Data("MacOnionSessionKey".utf8),
            outputByteCount: 32
        )
        
        return (clientEphemeralPublicKeyData, symmetricKey)
    }
    
    public enum KeyExchangeError: Error {
        case invalidPublicKey
    }
}
