import Foundation
import Testing
@testable import DeskwardenKit

struct FrameDecoderTests {
    @Test func reassemblesFrameSplitAcrossChunks() throws {
        let frame = FrameDecoder.encode(Data("hello".utf8))
        var decoder = FrameDecoder()
        decoder.append(frame.prefix(3))
        #expect(try decoder.nextFrame() == nil)
        decoder.append(frame.dropFirst(3))
        #expect(try decoder.nextFrame() == Data("hello".utf8))
        #expect(try decoder.nextFrame() == nil)
    }

    @Test func splitsSeveralFramesInOneChunk() throws {
        var decoder = FrameDecoder()
        decoder.append(FrameDecoder.encode(Data("a".utf8)) + FrameDecoder.encode(Data()) + FrameDecoder.encode(Data("bc".utf8)))
        #expect(try decoder.nextFrame() == Data("a".utf8))
        #expect(try decoder.nextFrame() == Data())
        #expect(try decoder.nextFrame() == Data("bc".utf8))
        #expect(try decoder.nextFrame() == nil)
    }

    @Test func rejectsOversizedFrames() {
        var decoder = FrameDecoder()
        decoder.append(Data([0x7F, 0xFF, 0xFF, 0xFF]))
        #expect(throws: FrameDecoder.FrameTooLarge.self) {
            try decoder.nextFrame()
        }
    }
}
