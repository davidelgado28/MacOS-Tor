import Foundation
import CryptoKit

public class OnionCrypter {
    private let keys: [SymmetricKey]
    
    public init(keys: [SymmetricKey]) {
        self.keys = keys
    }

    public func encryptOnion(payload: Data) throws -> Data {
        var currentData = payload
      
        for key in keys.reversed() {
            let nonce = ChaChaPoly.Nonce()
            let sealedBox = try ChaChaPoly.seal(currentData, using: key, nonce: nonce)
            currentData = sealedBox.combined 
        }
        return currentData
    }
    public func decryptOnion(payload: Data) throws -> Data {
        var currentData = payload
        
        for key in keys {
            let sealedBox = try ChaChaPoly.SealedBox(combined: currentData)
            currentData = try ChaChaPoly.open(sealedBox, using: key)
        }
        return currentData
    }
}
