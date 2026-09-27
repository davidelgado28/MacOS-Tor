import Foundation

public enum CellCommand: UInt8 {
    case padding     = 0x00 
    case create      = 0x01 
    case created     = 0x02 
    case relayData   = 0x03 
    case destroy     = 0x04 
}

public struct OnionCell {
    public static let cellSize = 512
    public static let headerSize = 14
    public static let payloadSize = cellSize - headerSize 
    
    public var command: CellCommand
    public var circuitID: UInt32
    public var streamID: UInt32
    public var payloadLength: UInt16
    public var payload: Data
    
    public init(command: CellCommand, circuitID: UInt32, streamID: UInt32, payload: Data) {
        self.command = command
        self.circuitID = circuitID
        self.streamID = streamID
        self.payloadLength = UInt16(min(payload.count, Self.payloadSize))
        
        var paddedPayload = payload.prefix(Self.payloadSize)
        if paddedPayload.count < Self.payloadSize {
            paddedPayload.append(Data(repeating: 0, count: Self.payloadSize - paddedPayload.count))
        }
        self.payload = paddedPayload
    }
  
    public func serialize() -> Data {
        var data = Data(capacity: Self.cellSize)
        data.append(command.rawValue)
        
        var cid = circuitID.bigEndian
        data.append(Data(bytes: &cid, count: 4))
        
        var sid = streamID.bigEndian
        data.append(Data(bytes: &sid, count: 4))
        
        var len = payloadLength.bigEndian
        data.append(Data(bytes: &len, count: 2))
        
        data.append(Data(repeating: 0, count: 3)) 
        data.append(payload)
        
        return data
    }
    
    public static func deserialize(from data: Data) -> OnionCell? {
        guard data.count == Self.cellSize else { return nil }
        guard let cmd = CellCommand(rawValue: data[0]) else { return nil }
        
        let cid = data.subdata(in: 1..<5).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let sid = data.subdata(in: 5..<9).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        let len = data.subdata(in: 9..<11).withUnsafeBytes { $0.load(as: UInt16.self).bigEndian }
        let payload = data.subdata(in: 14..<Self.cellSize)
        
        var cell = OnionCell(command: cmd, circuitID: cid, streamID: sid, payload: payload)
        cell.payloadLength = len
        return cell
    }
}
