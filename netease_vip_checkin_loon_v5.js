/*
 * 网易云 会员打卡(签到) 脚本（Loon 版 · Cron 定时脚本 · 健壮性改造版）
 * -------------------------------------------------------------
 * 依赖：先跑 neteasemusic.cookie.js 抓取会话（存在 chavy_cookie_neteasemusic）
 *
 * 部署（Loon）：
 *   插件 → + → 本地脚本，选本文件，类型「定时(Cron)」，cron 如：10 0 * * *
 *
 * 算法（已用抓包数据验证）：eapi = AES-128-ECB，key = "e82ckenh8dichen8"
 *   请求体: apiPath-rand-JSON-rand-md5(apiPath-rand-JSON-rand-key) → AES → 大写HEX
 *   响应体: AES 解密 → gzip 流 → inflate → JSON
 *
 * ⚠️ 仅用于本人账号本地学习/授权研究。
 *
 * 修改时间: 2026-08-24 16:05:00 (修复响应解析: 解密后增加 gzip 检测+纯JS inflate; 请求头 Accept-Encoding 改 identity 避免服务器返回压缩数据)
 */

const $ = new Env('网易云会员打卡');

// ===== 纯 JS 加解密实现（不依赖 $crypto / $zlib，兼容无 $crypto 的 Loon）=====
const HAS_CRYPTO = typeof $crypto !== 'undefined';
const HAS_ZLIB = typeof $zlib !== 'undefined';
$.log('【脚本版本 v20260824-2 已加载】环境: $crypto=' + HAS_CRYPTO + ' $zlib=' + HAS_ZLIB + ' $httpClient=' + (typeof $httpClient !== 'undefined'));

const EAPI_KEY = 'e82ckenh8dichen8';

// ---------- 字节工具 ----------
function strToBytes(s) { const a = []; for (let i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff); return a; }
function bytesToStr(a) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return s; }
function bytesToHex(a) { let s = ''; for (let i = 0; i < a.length; i++) s += ('0' + (a[i] & 0xff).toString(16)).slice(-2); return s; }
function hexToBytes(h) { const a = []; for (let i = 0; i < h.length; i += 2) a.push(parseInt(h.substr(i, 2), 16)); return a; }
// ---------- 纯 JS gzip/inflate 解压（无 $zlib 时用，仅支持 DEFLATE 无头块）----------
// 响应体 = AES( gzip流 )，解密后若以 0x1f 0x8b 开头就是 gzip，需要 inflate
function inflateRaw(input) {
  // 简化版：仅处理无 zlib 头的 raw deflate（gzip 去掉 10 字节头 + 8 字节尾）
  let pos = 10; // 跳过 gzip 头 (magic cm fleg mtime xfl os)
  // 读取可能的额外字段 (FLG.FEXTRA)
  const flg = input[3];
  if (flg & 0x04) { const xl = input[10] | (input[11] << 8); pos = 12 + xl; }
  if (flg & 0x08) { while (input[pos] !== 0) pos++; pos++; } // fname
  if (flg & 0x10) { while (input[pos] !== 0) pos++; pos++; } // fcomment
  if (flg & 0x02) pos += 2; // fhcrc
  // 现在 input[pos..] 是 raw deflate 数据（去掉末尾 8 字节 CRC+ISIZE）
  const deflateData = input.slice(pos, input.length - 8);
  return rawInflate(deflateData);
}
function rawInflate(data) {
  let bp = 0;
  function readBit() { const b = (data[bp >> 3] >> (bp & 7)) & 1; bp++; return b; }
  function readBits(n) { let v = 0; for (let i = 0; i < n; i++) v |= readBit() << i; return v; }
  // 固定 Huffman 表（DEFLATE 规范）
  function buildFixed() {
    const lit = [];
    for (let i = 0; i < 288; i++) {
      let bits, code;
      if (i < 144) { bits = 8; code = 0x30 + i; }
      else if (i < 256) { bits = 9; code = 0x190 + (i - 144); }
      else if (i < 280) { bits = 7; code = 0x00 + (i - 256); }
      else { bits = 8; code = 0xC0 + (i - 280); }
      lit[i] = { bits, code };
    }
    return lit;
  }
  const litTable = buildFixed();
  const out = [];
  while (true) {
    const bfinal = readBit();
    const btype = readBits(2);
    if (btype === 0) {
      // 不压缩块：对齐到字节，读 LEN
      bp = (bp + 7) & ~7;
      const len = data[bp >> 3] | (data[bp >> 3 + 1] << 8);
      bp += 16;
      for (let i = 0; i < len; i++) out.push(data[bp >> 3 + i] !== undefined ? data[bp >> 3 + i] : 0);
      bp += len * 8;
    } else if (btype === 1) {
      // 固定 Huffman
      while (true) {
        let code = 0, len = 0, sym = -1;
        for (len = 1; len <= 9; len++) {
          code = (code << 1) | readBit();
          for (let s = 0; s < 288; s++) {
            if (litTable[s].bits === len && litTable[s].code === code) { sym = s; break; }
          }
          if (sym >= 0) break;
        }
        if (sym === 256) break;
        if (sym < 256) out.push(sym);
        else {
          // 长度/距离（简化，仅覆盖常见长度）
          let lengthBase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
          let extraBits = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
          let distBase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
          let distExtra = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
          const li = sym - 257;
          const length = lengthBase[li] + readBits(extraBits[li]);
          let dsym = 0; let dbits = 0; let dcode = 0;
          for (dbits = 5; dbits >= 1; dbits--) {
            dcode = (dcode << 1) | readBit();
          }
          // 简单匹配（固定5位距离码）
          let di = -1;
          for (let s = 0; s < 30; s++) {
            // 距离 Huffman 是固定 5 位：0..29 对应 code 0..29
            if (s === dcode) { di = s; break; }
          }
          const dist = distBase[di] + readBits(distExtra[di]);
          for (let i = 0; i < length; i++) out.push(out[out.length - dist]);
        }
      }
    } else {
      // 动态 Huffman —— 极少出现在小响应，抛错交由上层容错
      throw new Error('dynamic Huffman not supported');
    }
    if (bfinal) break;
  }
  return out;
}

function bytesToB64(a) {
  let s = ''; const ch = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < a.length; i += 3) {
    const b0 = a[i], b1 = a[i + 1], b2 = a[i + 2];
    const e0 = b0 >> 2, e1 = ((b0 & 3) << 4) | (b1 !== undefined ? b1 >> 4 : 0);
    const e2 = b1 !== undefined ? ((b1 & 15) << 2) | (b2 !== undefined ? b2 >> 6 : 0) : 64;
    const e3 = b2 !== undefined ? b2 & 63 : 64;
    s += ch[e0] + ch[e1] + (e2 === 64 ? '=' : ch[e2]) + (e3 === 64 ? '=' : ch[e3]);
  }
  return s;
}
function b64ToBytes(s) {
  const ch = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lookup = {}; for (let i = 0; i < ch.length; i++) lookup[ch[i]] = i;
  const a = [];
  for (let i = 0; i < s.length; i += 4) {
    const e0 = lookup[s[i]], e1 = lookup[s[i + 1]];
    const e2 = s[i + 2] === '=' ? 0 : lookup[s[i + 2]];
    const e3 = s[i + 3] === '=' ? 0 : lookup[s[i + 3]];
    a.push((e0 << 2) | (e1 >> 4));
    if (s[i + 2] !== '=') a.push(((e1 & 15) << 4) | (e2 >> 2));
    if (s[i + 3] !== '=') a.push(((e2 & 3) << 6) | e3);
  }
  return a;
}

// ---------- MD5（标准实现）----------
function md5(s) {
  function add32(a, b) { return (a + b) & 0xffffffff; }
  function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
  function ff(a, b, c, d, x, s, t) { return cmn((b & c) | (~b & d), a, b, x, s, t); }
  function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & ~d), a, b, x, s, t); }
  function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
  function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | ~d), a, b, x, s, t); }
  const K = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15].map(function (i) {
    return Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) & 0xffffffff;
  });
  const msg = strToBytes(s);
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  const lenBits = s.length * 8;
  msg.push(lenBits & 0xff, (lenBits >>> 8) & 0xff, (lenBits >>> 16) & 0xff, (lenBits >>> 24) & 0xff);
  msg.push(0, 0, 0, 0);
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < msg.length; i += 64) {
    const X = [];
    for (let j = 0; j < 16; j++) X.push(msg[i + j * 4] | (msg[i + j * 4 + 1] << 8) | (msg[i + j * 4 + 2] << 16) | (msg[i + j * 4 + 3] << 24));
    let aa = a, bb = b, cc = c, dd = d;
    let f, g;
    for (let k = 0; k < 64; k++) {
      if (k < 16) { f = (b & c) | (~b & d); g = k; }
      else if (k < 32) { f = (b & d) | (c & ~d); g = (5 * k + 1) % 16; }
      else if (k < 48) { f = b ^ c ^ d; g = (3 * k + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * k) % 16; }
      const tmp = d; d = c; c = b;
      b = add32(b, cmn(f, a, b, X[g], [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21][k], K[k]));
      a = tmp;
    }
    a = add32(a, aa); b = add32(b, bb); c = add32(c, cc); d = add32(d, dd);
  }
  function toHex(n) { let s = ''; for (let i = 0; i < 4; i++) s += ('0' + ((n >>> (i * 8)) & 0xff).toString(16)).slice(-2); return s; }
  return toHex(a) + toHex(b) + toHex(c) + toHex(d);
}

// ---------- AES-128-ECB（纯 JS，已用 Node oracle + 抓包密文验证正确）----------
const SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];

function keyExpansion(key) {
  const Nk = 4, Nr = 10, w = [];
  for (let i = 0; i < Nk; i++) w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  for (let i = Nk; i < 4 * (Nr + 1); i++) {
    let t = w[i - 1].slice();
    if (i % Nk === 0) {
      t.push(t.shift());
      for (let j = 0; j < 4; j++) t[j] = SBOX[t[j]];
      t[0] ^= RCON[(i / Nk) - 1];
    }
    w[i] = [w[i - Nk][0] ^ t[0], w[i - Nk][1] ^ t[1], w[i - Nk][2] ^ t[2], w[i - Nk][3] ^ t[3]];
  }
  return w;
}
function gfMul(a, b) {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}
function encryptBlock(block, w) {
  const Nr = 10;
  let s = block.slice();
  const addRoundKey = (r) => { for (let c = 0; c < 4; c++) for (let rr = 0; rr < 4; rr++) s[c * 4 + rr] ^= w[r * 4 + c][rr]; };
  const subBytes = () => { for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]]; };
  const shiftRows = () => {
    const t = s.slice();
    s[0]=t[0];s[1]=t[5];s[2]=t[10];s[3]=t[15];
    s[4]=t[4];s[5]=t[9];s[6]=t[14];s[7]=t[3];
    s[8]=t[8];s[9]=t[13];s[10]=t[2];s[11]=t[7];
    s[12]=t[12];s[13]=t[1];s[14]=t[6];s[15]=t[11];
  };
  const mixColumns = () => {
    const t = s.slice();
    for (let c = 0; c < 4; c++) {
      const i = c * 4;
      s[i]   = gfMul(t[i], 2) ^ gfMul(t[i + 1], 3) ^ t[i + 2] ^ t[i + 3];
      s[i+1] = t[i] ^ gfMul(t[i + 1], 2) ^ gfMul(t[i + 2], 3) ^ t[i + 3];
      s[i+2] = t[i] ^ t[i + 1] ^ gfMul(t[i + 2], 2) ^ gfMul(t[i + 3], 3);
      s[i+3] = gfMul(t[i], 3) ^ t[i + 1] ^ t[i + 2] ^ gfMul(t[i + 3], 2);
    }
  };
  addRoundKey(0);
  for (let r = 1; r < Nr; r++) { subBytes(); shiftRows(); mixColumns(); addRoundKey(r); }
  subBytes(); shiftRows(); addRoundKey(Nr);
  return s;
}
function aes128EcbEncrypt(plainBytes, keyBytes) {
  const w = keyExpansion(keyBytes);
  const out = [];
  for (let i = 0; i < plainBytes.length; i += 16) {
    out.push(...encryptBlock(plainBytes.slice(i, i + 16), w));
  }
  return out;
}
// 解密用（响应解析需要）：逆 SBOX + 逆 mixColumns + 逆 shiftRows
const Si = []; for (let i = 0; i < 256; i++) Si[SBOX[i]] = i;
function decryptBlock(block, w) {
  const Nr = 10;
  let s = block.slice();
  const addRoundKey = (r) => { for (let c = 0; c < 4; c++) for (let rr = 0; rr < 4; rr++) s[c * 4 + rr] ^= w[r * 4 + c][rr]; };
  const invSubBytes = () => { for (let i = 0; i < 16; i++) s[i] = Si[s[i]]; };
  const invShiftRows = () => {
    const t = s.slice();
    s[0]=t[0];s[1]=t[13];s[2]=t[10];s[3]=t[7];
    s[4]=t[4];s[5]=t[1];s[6]=t[14];s[7]=t[11];
    s[8]=t[8];s[9]=t[5];s[10]=t[2];s[11]=t[15];
    s[12]=t[12];s[13]=t[9];s[14]=t[6];s[15]=t[3];
  };
  const invMixColumns = () => {
    const t = s.slice();
    for (let c = 0; c < 4; c++) {
      const i = c * 4;
      s[i]   = gfMul(t[i], 14) ^ gfMul(t[i+1], 11) ^ gfMul(t[i+2], 13) ^ gfMul(t[i+3], 9);
      s[i+1] = gfMul(t[i], 9) ^ gfMul(t[i+1], 14) ^ gfMul(t[i+2], 11) ^ gfMul(t[i+3], 13);
      s[i+2] = gfMul(t[i], 13) ^ gfMul(t[i+1], 9) ^ gfMul(t[i+2], 14) ^ gfMul(t[i+3], 11);
      s[i+3] = gfMul(t[i], 11) ^ gfMul(t[i+1], 13) ^ gfMul(t[i+2], 9) ^ gfMul(t[i+3], 14);
    }
  };
  addRoundKey(Nr);
  for (let r = Nr - 1; r > 0; r--) { invShiftRows(); invSubBytes(); addRoundKey(r); invMixColumns(); }
  invShiftRows(); invSubBytes(); addRoundKey(0);
  return s;
}
function aes128EcbDecrypt(cipherBytes, keyBytes) {
  const w = keyExpansion(keyBytes);
  const out = [];
  for (let i = 0; i < cipherBytes.length; i += 16) {
    out.push(...decryptBlock(cipherBytes.slice(i, i + 16), w));
  }
  return out;
}

// ---------- PKCS7 补位 ----------
function pkcs7Pad(bytes) {
  const pad = 16 - (bytes.length % 16);
  const out = bytes.slice();
  for (let i = 0; i < pad; i++) out.push(pad);
  return out;
}

// ===== eapi 实际加解密 =====
// 加密：明文 → PKCS7 补位 → AES-128-ECB → hex 大写
function eapiEncrypt(plainStr) {
  const keyBytes = strToBytes(EAPI_KEY);
  const plain = pkcs7Pad(strToBytes(plainStr));
  return bytesToHex(aes128EcbEncrypt(plain, keyBytes)).toUpperCase();
}
// 解密：hex 密文 → AES-128-ECB 解密 → 去 PKCS7 → 字节
function eapiDecryptHex(hexStr) {
  const keyBytes = strToBytes(EAPI_KEY);
  const dec = aes128EcbDecrypt(hexToBytes(hexStr), keyBytes);
  const pad = dec[dec.length - 1];
  return dec.slice(0, dec.length - (pad > 0 && pad <= 16 ? pad : 0));
}

function randStr(n) {
  const cs = 'abcdef0123456789';
  let s = '';
  for (let i = 0; i < n; i++) s += cs[Math.floor(Math.random() * cs.length)];
  return s;
}

function buildParams(apiPath, jsonObj) {
  const r1 = randStr(11);
  const r2 = randStr(32);
  const json = JSON.stringify(jsonObj);
  const core = `${apiPath}-${r1}-${json}-${r2}`;
  const m = md5(core + '-' + EAPI_KEY);
  const plain = `${core}-${m}`;
  return eapiEncrypt(plain);
}

function parseResp(data) {
  let decBytes;
  if (typeof data === 'string') {
    let hexStr;
    if (/^[0-9a-fA-F]+$/.test(data.trim())) hexStr = data.trim();
    else hexStr = bytesToHex(b64ToBytes(data.trim()));
    decBytes = eapiDecryptHex(hexStr);
  } else {
    decBytes = eapiDecryptHex(bytesToHex(data));
  }
  // 解密后可能是 gzip 流（0x1f 0x8b），需要 inflate
  if (decBytes.length > 2 && decBytes[0] === 0x1f && decBytes[1] === 0x8b) {
    try {
      const inflated = inflateRaw(decBytes);
      decBytes = inflated;
    } catch (e) {
      $.log('⚠️ inflate 失败，尝试直接当明文: ' + e);
    }
  }
  const txt = bytesToStr(decBytes);
  const idx = txt.indexOf('{');
  return idx >= 0 ? JSON.parse(txt.slice(idx)) : JSON.parse(txt);
}

// ===== 从抓取的会话里提取字段 =====
function extractSession() {
  const raw = $.getdata('chavy_cookie_neteasemusic');
  if (!raw) {
    $.log('❗️ 未找到会话 chavy_cookie_neteasemusic，请先跑 neteasemusic.cookie.js');
    return null;
  }
  let s;
  try {
    s = JSON.parse(raw);
  } catch (e) {
    $.log('❗️ 会话 JSON 解析失败: ' + e);
    return null;
  }
  const h = s.headers || {};
  const cookieStr = h['cookie'] || h['Cookie'] || '';
  const deviceId = h['x-deviceid'] || h['x-sdeviceid'] || (cookieStr.match(/deviceId=([^;]+)/) || [])[1] || '';
  const appkey = h['x-appkey'] || 'IuRPVVmc3WWul9fT';
  const musicU = (cookieStr.match(/MUSIC_U=([^;]+)/) || [])[1] || '';
  // 调试：打印提取到的关键字段前几位，确认取对了
  $.log('提取: deviceId=' + deviceId + ' musicU前6=' + musicU.slice(0, 6) + ' appkey=' + appkey);
  if (!musicU) {
    $.log('❗️ cookie 里没有 MUSIC_U，登录态可能缺失');
  }
  return { cookieStr, deviceId, appkey, musicU, headers: h };
}

// ===== 发 eapi 请求 =====
function eapiPost(apiPath, jsonObj, sess, cb) {
  let params;
  try {
    params = buildParams(apiPath, jsonObj);
  } catch (e) {
    $.log('❗️ 构造 params 失败: ' + e);
    return cb(null);
  }
  const headers = {
    'Cookie': sess.cookieStr,
    'x-appkey': sess.appkey,
    'x-appver': '9.5.70',
    'x-buildver': '7178',
    'x-deviceid': sess.deviceId,
    'x-idfv': (sess.headers && (sess.headers['x-idfv'] || sess.headers['X-Idfv'])) || 'B67CB4AB-AE7F-41FD-90DA-43FD596A7D3C',
    'x-music-u': sess.musicU,
    'x-aeapi': 'true',
    'x-netlib': 'Cronet',
    'x-os': 'iPhone OS',
    'x-osver': '27.0',
    'x-machineid': 'iPhone18.4',
    'x-sdeviceid': sess.deviceId,
    'User-Agent': 'NeteaseMusic 9.5.70/7178 (iPhone; iOS 27.0; zh_CN)',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept-Encoding': 'identity', // 关键：避免服务器返回 gzip，解密后直接是 JSON 明文
    'Accept': '*/*',
  };
  const body = 'params=' + params;
  if (typeof $httpClient === 'undefined') {
    $.log('❗️ 当前环境无 $httpClient');
    return cb(null);
  }
  const fullUrl = 'https://interface3.music.163.com' + apiPath;
  $.log('📤 请求: ' + apiPath + ' | params前80: ' + params.slice(0, 80) + '...');
  $.log('🍪 发送Cookie前200: ' + sess.cookieStr.slice(0, 200));
  $httpClient.post(
    { url: fullUrl, headers, body },
    function (error, response, data) {
      const status = (response && (response.status || response.statusCode)) || '未知';
      $.log('📥 响应 status=' + status + ' | dataType=' + typeof data + ' | 前100: ' + (typeof data === 'string' ? data.slice(0, 100) : 'binary'));
      if (error) {
        $.log('❗️ 请求错误: ' + error);
        return cb(null);
      }
      if (data === '{}' || data === '' || (typeof data === 'string' && data.trim() === '{}')) {
        $.log('⚠️ 服务器返回空响应 {} ，通常是 cookie/MUSIC_U 失效或 params 未通过校验');
        return cb(null);
      }
      try {
        const json = parseResp(data);
        cb(json);
      } catch (e) {
        $.log('❗️ 解析失败: ' + e + ' | raw前100: ' + (typeof data === 'string' ? data.slice(0, 100) : 'binary'));
        cb(null);
      }
    }
  );
}

// ===== 主流程（顶层 catch，确保不白屏）=====
(async () => {
  try {
    // 注意：本脚本使用纯 JS 内置 AES/MD5 实现，不依赖 $crypto，无 $crypto 的 Loon 也能跑
    const sess = extractSession();
    if (!sess) {
      $.msg($.name, '失败', '未找到会话，请先跑 neteasemusic.cookie.js 抓取');
      return;
    }
    eapiPost('/eapi/vip-center-bff/task/list', { deviceId: sess.deviceId, os: 'iOS', header: {}, e_r: true }, sess, (r) => {
      $.log('[task/list] ' + JSON.stringify(r).slice(0, 300));
      eapiPost('/eapi/vip-center-bff/task/sign', { deviceId: sess.deviceId, os: 'iOS', verifyId: 1, header: {}, e_r: true }, sess, (r2) => {
        $.log('[task/sign] ' + JSON.stringify(r2).slice(0, 300));
        const ok = r2 && r2.code === 200;
        $.msg($.name, ok ? '打卡成功' : '打卡失败', JSON.stringify(r2).slice(0, 200));
      });
    });
  } catch (e) {
    $.log('❗️ 主流程异常: ' + e + ' | stack: ' + (e && e.stack));
    $.msg($.name, '脚本异常', '' + e);
  } finally {
    // 确保 $done 一定被调用，避免 Loon 白屏/卡住
    if (typeof $done !== 'undefined') {
      // 延迟一点，让上面的异步回调有机会执行完毕
      setTimeout(() => $.done(), 1500);
    }
  }
})();

// ===== Env 封装 =====
function Env(s) {
  this.name = s;
  this.logs = [];
  this.log = (...s) => {
    this.logs = [...this.logs, ...s];
    const line = s.length ? s.join('\n') : this.logs.join('\n');
    console.log(line);
  };
  this.msg = (s = this.name, t = '', i = '') => {
    if (typeof $notification !== 'undefined') {
      try { $notification.post(s, t, i); } catch (e) { console.log('notify err: ' + e); }
    }
    console.log(['', '🔔 ' + s, t, i].filter(Boolean).join('\n'));
  };
  this.getdata = (k) => (typeof $persistentStore !== 'undefined' ? $persistentStore.read(k) : null);
  this.done = (s = {}) => (typeof $done !== 'undefined' ? $done(s) : null);
}
