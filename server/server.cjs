const http = require("node:http");
const net = require("node:net");
const dns = require("node:dns").promises;
const crypto = require("node:crypto");
const { WebSocketServer } = require("ws");
const { publicIP, target } = require("../src/tunnel-policy.cjs");

function createTunnelServer({ token, loopbackOnly = false }) {
  if (!token)
    throw Error("BHAPPY_TOKEN is missing. Add it in Render > Environment.");
  // Render generateValue creates a Base64-encoded 256-bit secret, including '=' padding.
  // Keep the same alphabet as the existing clients, without whitespace or header injection.
  if (typeof token !== "string" || !/^[A-Za-z0-9_+=/.-]{32,256}$/.test(token))
    throw Error(
      "BHAPPY_TOKEN must contain 32–256 letters, digits or _ + = / . - (Base64 supported).",
    );
  const server = http.createServer((req, res) => {
    res.writeHead(req.url === "/healthz" ? 200 : 404, {
      "Content-Type": "text/plain",
    });
    res.end(req.url === "/healthz" ? "BHappy tunnel" : "Not found");
  });
  const wss = new WebSocketServer({
    noServer: true,
    maxPayload: 65536,
    perMessageDeflate: false,
  });
  server.on("upgrade", (req, socket, head) => {
    const supplied = Buffer.from(req.headers.authorization || ""),
      expected = Buffer.from("Bearer " + token);
    if (
      req.url !== "/tunnel" ||
      supplied.length !== expected.length ||
      !crypto.timingSafeEqual(supplied, expected)
    ) {
      socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws));
  });
  wss.on("connection", (ws) => {
    let upstream,
      initialized = false;
    const timeout = setTimeout(() => ws.terminate(), 15000);
    const close = () => {
      clearTimeout(timeout);
      if (upstream) upstream.destroy();
      ws.terminate();
    };
    ws.on("error", close);
    ws.on("close", close);
    ws.on("message", async (data, binary) => {
      if (!initialized) {
        initialized = true;
        try {
          if (binary || data.length > 512) return close();
          const command = JSON.parse(data);
          if (command.ping === true) {
            clearTimeout(timeout);
            ws.send('{"ready":true}');
            return;
          }
          const { host, port } = target(command);
          if (loopbackOnly && !["localhost", "127.0.0.1", "::1"].includes(host))
            return close();
          const addresses = await dns.lookup(host, { all: true });
          if (
            !addresses.length ||
            addresses.some(({ address }) =>
              loopbackOnly
                ? !(address === "::1" || address.startsWith("127."))
                : !publicIP(address),
            )
          )
            return close();
          if (ws.readyState !== ws.OPEN) return close();
          upstream = net.connect({
            host,
            port,
            autoSelectFamily: true,
            lookup: (_host, options, callback) =>
              options.all
                ? callback(null, addresses)
                : callback(null, addresses[0].address, addresses[0].family),
          });
          upstream.once("connect", () => {
            clearTimeout(timeout);
            ws.send('{"ready":true}');
          });
          upstream.on("data", (chunk) => {
            upstream.pause();
            ws.send(chunk, { binary: true }, (error) =>
              error ? close() : upstream.resume(),
            );
          });
          upstream.on("drain", () => ws.resume());
          upstream.on("error", close);
          upstream.on("close", () => ws.close(1000));
        } catch {
          close();
        }
        return;
      }
      if (!binary || !upstream || upstream.connecting) return close();
      if (!upstream.write(data)) ws.pause();
    });
  });
  return {
    server,
    close: async () => {
      for (const ws of wss.clients) ws.terminate();
      await new Promise((r) => server.close(r));
    },
  };
}
if (require.main === module) {
  const instance = createTunnelServer({ token: process.env.BHAPPY_TOKEN });
  instance.server.listen(Number(process.env.PORT || 3000), "0.0.0.0", () =>
    console.log("BHappy tunnel server listening"),
  );
}
module.exports = { createTunnelServer };
