const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const size = 256;
const pixels = Buffer.alloc(size * size * 4);

function insideTriangle(x, y, a, b, c) {
  const cross = (p, q, r) => (q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x);
  const first = cross(a, b, { x, y });
  const second = cross(b, c, { x, y });
  const third = cross(c, a, { x, y });
  return (first >= 0 && second >= 0 && third >= 0) || (first <= 0 && second <= 0 && third <= 0);
}

function setPixel(x, y, color) {
  const offset = (y * size + x) * 4;
  pixels[offset] = color[0];
  pixels[offset + 1] = color[1];
  pixels[offset + 2] = color[2];
  pixels[offset + 3] = 255;
}

const compass = [{ x: 160, y: 76 }, { x: 142, y: 150 }, { x: 84, y: 190 }];
const coral = [{ x: 160, y: 76 }, { x: 106, y: 112 }, { x: 142, y: 150 }];

for (let y = 0; y < size; y++) {
  for (let x = 0; x < size; x++) {
    const dx = x - 128;
    const dy = y - 128;
    const distance = Math.hypot(dx, dy);
    let color = null;

    if (distance <= 119 && distance >= 112) color = [213, 224, 220];
    else if (distance <= 112) color = [24, 39, 45];
    if (distance <= 88 && distance >= 85) color = [91, 121, 124];

    const cardinal = Math.abs(dx) < 3 || Math.abs(dy) < 3;
    if (distance >= 94 && distance <= 104 && cardinal) color = [215, 229, 223];

    if (insideTriangle(x, y, ...compass)) color = [63, 180, 177];
    if (insideTriangle(x, y, ...coral)) color = [240, 120, 98];
    if (distance <= 8) color = [239, 245, 239];
    if (distance <= 5 && distance >= 3) color = [24, 39, 45];
    if (color) setPixel(x, y, color);
  }
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const name = Buffer.from(type);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, checksum]);
}

const scanlines = Buffer.alloc(size * (size * 4 + 1));
for (let y = 0; y < size; y++) {
  const row = y * (size * 4 + 1);
  pixels.copy(scanlines, row + 1, y * size * 4, (y + 1) * size * 4);
}
const header = Buffer.alloc(13);
header.writeUInt32BE(size, 0);
header.writeUInt32BE(size, 4);
header[8] = 8;
header[9] = 6;
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  pngChunk('IHDR', header),
  pngChunk('IDAT', zlib.deflateSync(scanlines)),
  pngChunk('IEND', Buffer.alloc(0)),
]);

const directory = Buffer.alloc(22);
directory.writeUInt16LE(1, 2);
directory.writeUInt16LE(1, 4);
directory[6] = 0;
directory[7] = 0;
directory.writeUInt16LE(1, 10);
directory.writeUInt16LE(32, 12);
directory.writeUInt32LE(png.length, 14);
directory.writeUInt32LE(directory.length, 18);

const output = path.join(__dirname, '..', 'assets', 'safari.ico');
fs.writeFileSync(output, Buffer.concat([directory, png]));
console.log(`Generated ${output}`);