const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const DIELINES = path.join(ROOT, 'pi-specs-dielines');

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.pdf': 'application/pdf', '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
};

function parseMultipart(body, boundary) {
  const parts = [];
  const sep = Buffer.from('--' + boundary);
  const end = Buffer.from('--' + boundary + '--');
  let pos = 0;
  while (pos < body.length) {
    const start = indexOf(body, sep, pos);
    if (start === -1) break;
    pos = start + sep.length;
    if (body.slice(pos, pos + 2).toString() === '--') break;
    pos += 2; // skip \r\n
    const headerEnd = indexOf(body, Buffer.from('\r\n\r\n'), pos);
    if (headerEnd === -1) break;
    const headers = body.slice(pos, headerEnd).toString();
    pos = headerEnd + 4;
    const nextSep = indexOf(body, sep, pos);
    const data = body.slice(pos, nextSep - 2); // strip trailing \r\n
    pos = nextSep;
    const nameMatch = headers.match(/name="([^"]+)"/);
    const fileMatch = headers.match(/filename="([^"]+)"/);
    parts.push({ name: nameMatch ? nameMatch[1] : '', filename: fileMatch ? fileMatch[1] : '', data });
  }
  return parts;
}

function indexOf(buf, search, offset) {
  offset = offset || 0;
  for (let i = offset; i <= buf.length - search.length; i++) {
    let found = true;
    for (let j = 0; j < search.length; j++) {
      if (buf[i + j] !== search[j]) { found = false; break; }
    }
    if (found) return i;
  }
  return -1;
}

const server = http.createServer(function(req, res) {
  // CORS for local dev
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // POST /upload-dieline  → save PDF to pi-specs-dielines/
  if (req.method === 'POST' && req.url === '/upload-dieline') {
    const ct = req.headers['content-type'] || '';
    const boundaryMatch = ct.match(/boundary=(.+)/);
    if (!boundaryMatch) { res.writeHead(400); res.end('No boundary'); return; }
    const boundary = boundaryMatch[1];
    const chunks = [];
    req.on('data', function(c) { chunks.push(c); });
    req.on('end', function() {
      const body = Buffer.concat(chunks);
      const parts = parseMultipart(body, boundary);
      const filePart = parts.find(function(p) { return p.filename; });
      if (!filePart) { res.writeHead(400); res.end('No file'); return; }
      // Sanitize filename
      const filename = path.basename(filePart.filename).replace(/[^a-zA-Z0-9._-]/g, '_');
      const dest = path.join(DIELINES, filename);
      fs.writeFile(dest, filePart.data, function(err) {
        if (err) { res.writeHead(500); res.end('Write failed'); return; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, filename: filename }));
      });
    });
    return;
  }

  // DELETE /delete-dieline?file=name.pdf
  if (req.method === 'DELETE' && req.url.startsWith('/delete-dieline')) {
    const file = new URL(req.url, 'http://x').searchParams.get('file');
    if (!file) { res.writeHead(400); res.end(); return; }
    const target = path.join(DIELINES, path.basename(file));
    fs.unlink(target, function() { res.writeHead(200); res.end(); });
    return;
  }

  // Serve static files
  let filePath = path.join(ROOT, req.url === '/' ? 'index.html' : req.url);
  // Prevent directory traversal
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
  fs.readFile(filePath, function(err, data) {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
});

var PORT = process.env.PORT || 3000;
server.listen(PORT, function() {
  console.log('PI Specs running at http://localhost:' + PORT);
  console.log('Die lines saved to: ' + DIELINES);
});
