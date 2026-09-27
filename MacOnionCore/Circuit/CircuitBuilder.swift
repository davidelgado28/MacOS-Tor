import Foundation
import CryptoKit

public class CircuitBuilder {
    private let directoryURL: URL
    public private(set) var activeNodes: [RelayNode] = []
    public private(set) var crypter: OnionCrypter?
    
    public init(directoryURL: URL) {
        self.directoryURL = directoryURL
    }
    
    public func fetchRelays() async throws -> [RelayNode] {
        let (data, _) = try await URLSession.shared.data(from: directoryURL)
        return try JSONDecoder().decode([RelayNode].self, from: data)
    }
    
    public func build3HopCircuit() async throws -> OnionCrypter {
        let relays = try await fetchRelays()
        guard relays.count >= 3 else {
            throw CircuitError.insufficientRelays
        }
        
        let selected = Array(relays.shuffled().prefix(3))
        self.activeNodes = selected
        
        print("[MacOnion Circuit] Rota selecionada:")
        print(" ├─ [Guard]  \(selected[0].nickname) (\(selected[0].ipAddress):\(selected[0].port))")
        print(" ├─ [Middle] \(selected[1].nickname) (\(selected[1].ipAddress):\(selected[1].port))")
        print(" └─ [Exit]   \(selected[2].nickname) (\(selected[2].ipAddress):\(selected[2].port))")
        
        var keys: [SymmetricKey] = []
        
        for (idx, node) in selected.enumerated() {
            print("[MacOnion] Negociando chave com Salto \(idx + 1) [\(node.nickname)].")
            let (_, sessionKey) = try KeyExchange.deriveSharedKey(peerPublicKeyBase64: node.publicKeyBase64)
            keys.append(sessionKey)
        }
        let onionCrypter = OnionCrypter(keys: keys)
        self.crypter = onionCrypter
        print("[MacOnion] Circuito estabelecido com sucesso!")
        return onionCrypter
    }
    public enum CircuitError: Error {
        case insufficientRelays
    }
}
