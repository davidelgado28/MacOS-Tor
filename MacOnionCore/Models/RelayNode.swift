import Foundation

public struct RelayNode: Codable, Identifiable, Hashable {
    public let id: UUID
    public let nickname: String
    public let ipAddress: String
    public let port: UInt16
    public let publicKeyBase64: String 
    
    public init(id: UUID = UUID(), nickname: String, ipAddress: String, port: UInt16, publicKeyBase64: String) {
        self.id = id
        self.nickname = nickname
        self.ipAddress = ipAddress
        self.port = port
        self.publicKeyBase64 = publicKeyBase64
    }
}
