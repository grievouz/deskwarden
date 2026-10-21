// Renders one element of an SVG into an 18 pt vector PDF for the menu bar,
// cropped to the element's bounds with a 16 pt tall glyph. The app draws it as
// a template image, so only the shape matters, not its colors.
//
//   swift scripts/make-menu-bar-icon.swift <input.svg> <element-id> <output.pdf>
import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 4 else {
    FileHandle.standardError.write(Data("usage: make-menu-bar-icon.swift <input.svg> <element-id> <output.pdf>\n".utf8))
    exit(64)
}

// Keep only the requested element, filled black.
let source = try XMLDocument(contentsOf: URL(fileURLWithPath: arguments[1]))
guard let root = source.rootElement(),
      let viewBox = root.attribute(forName: "viewBox")?.stringValue,
      let element = try source.nodes(forXPath: "//*[@id='\(arguments[2])']").first as? XMLElement
else {
    FileHandle.standardError.write(Data("no element with id \(arguments[2])\n".utf8))
    exit(1)
}
element.removeAttribute(forName: "class")
element.addAttribute(XMLNode.attribute(withName: "fill", stringValue: "#000") as! XMLNode)
let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"\(viewBox)\">\(element.xmlString)</svg>"
guard let image = NSImage(data: Data(svg.utf8)) else {
    FileHandle.standardError.write(Data("couldn't render the SVG\n".utf8))
    exit(1)
}

// Find the glyph's bounds by rasterizing once.
let side = Int(image.size.width)
let raster = NSBitmapImageRep(
    bitmapDataPlanes: nil, pixelsWide: side, pixelsHigh: side, bitsPerSample: 8, samplesPerPixel: 4,
    hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
)!
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: raster)
image.draw(in: NSRect(x: 0, y: 0, width: side, height: side))
var (minX, minY, maxX, maxY) = (side, side, 0, 0)
for y in 0..<side {
    for x in 0..<side where (raster.colorAt(x: x, y: y)?.alphaComponent ?? 0) > 0.05 {
        (minX, maxX, minY, maxY) = (min(minX, x), max(maxX, x), min(minY, y), max(maxY, y))
    }
}
// colorAt counts rows from the top; image coordinates count from the bottom.
let glyph = NSRect(x: minX, y: side - maxY - 1, width: maxX - minX + 1, height: maxY - minY + 1)

var box = CGRect(x: 0, y: 0, width: 18, height: 18)
let height: CGFloat = 16
let width = height * glyph.width / glyph.height
let data = NSMutableData()
let context = CGContext(consumer: CGDataConsumer(data: data)!, mediaBox: &box, nil)!
context.beginPDFPage(nil)
NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
image.draw(in: NSRect(x: (18 - width) / 2, y: 1, width: width, height: height), from: glyph, operation: .sourceOver, fraction: 1)
context.endPDFPage()
context.closePDF()
try data.write(to: URL(fileURLWithPath: arguments[3]))
