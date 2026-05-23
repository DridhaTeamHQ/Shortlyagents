const http = require("http");
const fs = require("fs");
const path = require("path");

const host = "127.0.0.1";
const port = 4173;
const baseDir = __dirname;

const mimeTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
};

function send(res, statusCode, body, contentType) {
  res.writeHead(statusCode, { "Content-Type": contentType });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const requestPath = decodeURIComponent((req.url || "/").split("?")[0]);
  const safePath = requestPath === "/" ? "index.html" : requestPath.replace(/^\/+/, "");
  const filePath = path.resolve(baseDir, safePath);

  if (!filePath.startsWith(baseDir)) {
    send(res, 403, "Forbidden", "text/plain; charset=utf-8");
    return;
  }

  fs.stat(filePath, (statError, stats) => {
    const finalPath = !statError && stats.isDirectory() ? path.join(filePath, "index.html") : filePath;

    fs.readFile(finalPath, (readError, data) => {
      if (readError) {
        send(res, 404, "Not found", "text/plain; charset=utf-8");
        return;
      }

      const extension = path.extname(finalPath).toLowerCase();
      send(res, 200, data, mimeTypes[extension] || "application/octet-stream");
    });
  });
});

server.listen(port, host, () => {
  console.log(`Local server running at http://${host}:${port}`);
});
