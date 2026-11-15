const { isIP } = require("node:net");
function tunnelEndpoint(value) {
  const url = new URL(value);
  if (url.username || url.password || url.hash || url.search)
    throw Error(
      "Адрес туннеля не должен содержать пароль, query или fragment.",
    );
  if (
    url.protocol !== "wss:" &&
    !(
      url.protocol === "ws:" &&
      ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    )
  )
    throw Error("Для туннеля нужен защищённый адрес wss://.");
  return url.href;
}
function credentials(url, token) {
  if (typeof token !== "string" || !/^[A-Za-z0-9_+=/.-]{32,256}$/.test(token))
    throw Error("Ключ туннеля должен содержать 32–256 букв, цифр, - или _.");
  return { url: tunnelEndpoint(url), token };
}
function publicIP(ip) {
  if (isIP(ip) === 4) {
    const [a, b, c] = ip.split(".").map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 &&
        (b === 168 ||
          (b === 0 && [0, 2].includes(c)) ||
          (b === 88 && c === 99))) ||
      (a === 198 && ([18, 19].includes(b) || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  // Only global unicast, excluding documentation and transition/embedded IPv4 ranges.
  const [first, second] = ip.split(":").map((x) => parseInt(x || "0", 16));
  return (
    isIP(ip) === 6 &&
    /^[23]/i.test(ip) &&
    first !== 0x2002 &&
    first !== 0x3fff &&
    !(first === 0x2001 && (second < 0x200 || second === 0xdb8))
  );
}
function target(value) {
  if (
    !value ||
    typeof value.host !== "string" ||
    value.host.length > 253 ||
    !/^[a-zA-Z0-9.:_-]+$/.test(value.host) ||
    !Number.isInteger(value.port) ||
    value.port < 1 ||
    value.port > 65535
  )
    throw Error("Invalid tunnel destination");
  return value;
}
module.exports = { tunnelEndpoint, credentials, publicIP, target };
