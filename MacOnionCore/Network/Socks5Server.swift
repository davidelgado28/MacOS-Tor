import Foundation
import Network

public class Socks5Server {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "org.maconion.socks5")
    public var onConnectRequest: ((_ host: String, _ port: UInt16, _ clientConnection: NWConnection) -> Void)?
    
    public init(port: UInt16 = 9050) throws {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        self.listener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: port)!)
    }
    public func start() {
        listener.newConnectionHandler = { [weak self] newConnection in
            self?.handleClientConnection(newConnection)
        }
        listener.stateUpdateHandler = { state in
            if case .ready = state {
                print("[SOCKS5] Proxy local escutando em 127.0.0.1:9050")
            }
        }
        listener.start(queue: queue)
    }
    private func handleClientConnection(_ connection: NWConnection) {
        connection.start(queue: queue)
        
        connection.receive(minimumIncompleteLength: 2, maximumLength: 257) { [weak self] data, _, _, error in
            guard let data = data, data.count >= 2, data[0] == 0x05 else {
                connection.cancel()
                return
            }
            
            let response = Data([0x05, 0x00])
            connection.send(content: response, completion: .contentProcessed({ _ in
                self?.handleSocksRequest(connection)
            }))
        }
    }
    private func handleSocksRequest(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 4, maximumLength: 512) { [weak self] data, _, _, error in
            guard let data = data, data.count >= 4, data[0] == 0x05, data[1] == 0x01 else {
                connection.cancel()
                return
            }
            let addressType = data[3]
            var destinationHost = ""
            var destinationPort: UInt16 = 0
            
            if addressType == 0x03 { 
                let domainLen = Int(data[4])
                guard data.count >= 5 + domainLen + 2 else { connection.cancel(); return }
                let domainData = data.subdata(in: 5..<(5 + domainLen))
                destinationHost = String(data: domainData, encoding: .utf8) ?? ""
                
                let portOffset = 5 + domainLen
                destinationPort = data.subdata(in: portOffset..<(portOffset + 2)).withUnsafeBytes {
                    $0.load(as: UInt16.self).bigEndian
                }
            } else if addressType == 0x01 { // IPv4
                guard data.count >= 10 else { connection.cancel(); return }
                let ipData = data.subdata(in: 4..<8)
                destinationHost = ipData.map { String($0) }.joined(separator: ".")
                destinationPort = data.subdata(in: 8..<10).withUnsafeBytes {
                    $0.load(as: UInt16.self).bigEndian
                }
            } else {
                connection.cancel()
                return
            }
            print("[SOCKS5] Conectando a \(destinationHost):\(destinationPort) via circuito Onion...")
            
            let reply = Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            connection.send(content: reply, completion: .contentProcessed({ _ in
                self?.onConnectRequest?(destinationHost, destinationPort, connection)
            }))
        }
    }
}
