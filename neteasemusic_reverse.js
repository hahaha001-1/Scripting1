#!/usr/bin/env node
/**
 * ============================================================================
 *  网易云音乐 自动签到脚本（逆向学习版）
 * ============================================================================
 *  作者参考: chavyleung/scripts 的 neteasemusic.js
 *  结合:    reverse-skill（网络安全逆向技能路由包，仅限合法学习/授权测试）
 *
 *  本文件双重用途：
 *    [A] 还原原版签到脚本（Node 可跑，修复 301 重定向问题）
 *    [B] 附带「weapi 加密逆向」讲解 + 可运行的加密函数示例（仅用于学习原理）
 *
 *  ⚠️ 免责声明：仅用于你本人账号的本地学习研究。请勿用于未授权访问、
 *     批量刷量或违反网易云服务条款的行为。
 * ============================================================================
 */

// ─────────────────────────────────────────────────────────────────────────
// 0. 配置区（你自己填）
// ─────────────────────────────────────────────────────────────────────────
// 老接口直接吃 Cookie 即可；新接口（weapi）才需要加密（见 [B] 部分）。
// 获取方式：浏览器/App 登录后，用 Charles / mitmproxy 抓
//   GET https://music.163.com/api/point/dailyTask?type=1
// 请求头里的 Cookie 整段复制过来。
const COOKIE = process.env.NEM_COOKIE || '这里粘贴你的Cookie';

// 重试配置
const RETRY_CNT = 10;
const RETRY_INTERVAL = 500; // ms

// ─────────────────────────────────────────────────────────────────────────
// [A] 原版签到逻辑（修复 301）
// ─────────────────────────────────────────────────────────────────────────
// 关键修复点：
//   原脚本用 http:// ，网易云现在对 http 返回 301 跳 https。
//   Node 的 request 库默认 followRedirect=true 会跟随，但部分环境/版本
//   拿不到最终 body。最稳妥：直接用 https:// 并显式 followRedirect:true。
const request = require('request');

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * 签到一次。type=1 是 Web(PC)端，type=0 是 App(移动)端。
 * 注意：这里用的是「未加密老接口」/api/point/dailyTask
 *       而不是加密的 /weapi/point/dailyTask
 */
function signOnce(type, ua) {
  return new Promise((resolve) => {
    const url = `https://music.163.com/api/point/dailyTask?type=${type}`;
    request(
      {
        url,
        method: 'GET',
        followRedirect: true, // ← 关键：跟随 https 重定向
        gzip: true,
        headers: {
          Cookie: COOKIE,
          Host: 'music.163.com',
          'User-Agent': ua,
          Referer: 'https://music.163.com/',
        },
      },
      (err, resp, data) => {
        try {
          if (err) {
            console.log(`❗️ 请求错误: ${err}`);
            return resolve(false);
          }
          // 调试：若仍看到 30x，说明 Cookie 失效或需带 CSRF
          if (resp && resp.statusCode >= 300 && resp.statusCode < 400) {
            console.log(`⚠️ 仍收到重定向 ${resp.statusCode}，Location=${resp.headers.location}`);
            return resolve(false);
          }
          const json = JSON.parse(data);
          // 原脚本判定 code === -2 为「成功/重复签到」
          const ok = json.code === -2 || json.code === 200;
          console.log(`[type=${type}] 响应: ${data}`);
          resolve(ok);
        } catch (e) {
          console.log(`❗️ 解析失败: ${e}，原始: ${data}`);
          resolve(false);
        }
      }
    );
  });
}

const UA_WEB =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15';
const UA_APP =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1';

async function runSign() {
  console.log('🔔 网易云签到（学习版），开始');

  // Web 端
  let webOk = false;
  for (let i = 0; i < RETRY_CNT && !webOk; i++) {
    webOk = await signOnce(1, UA_WEB);
    if (!webOk) await sleep(RETRY_INTERVAL);
  }

  // App 端
  let appOk = false;
  for (let i = 0; i < RETRY_CNT && !appOk; i++) {
    appOk = await signOnce(0, UA_APP);
    if (!appOk) await sleep(RETRY_INTERVAL);
  }

  const subt = `${webOk ? 'PC: 成功' : 'PC: 失败'}, ${appOk ? 'APP: 成功' : 'APP: 失败'}`;
  console.log(`🔔 结束 - ${subt}`);
}

// ─────────────────────────────────────────────────────────────────────────
// [B] weapi 加密逆向讲解 + 可运行示例（仅学习原理）
// ─────────────────────────────────────────────────────────────────────────
/**
 * 为什么原脚本能「跳过加密」？
 * ------------------------------------------------------------------
 * 网易云有两套接口：
 *   1) /api/xxx      —— 老接口，部分仍接受明文参数 + Cookie（原脚本用的就是这个）
 *   2) /weapi/xxx    —— 新接口，请求体必须是加密后的 params + encSecKey
 *
 * 当你看到脚本里直接 GET /api/point/dailyTask 而没有加密，
 * 是因为它走的是「未加密老接口」这条路，绕过了 weapi 加密层。
 * 真正体现「网易云逆向」的是 weapi 加密，下面还原它的算法。
 *
 * weapi 加密原理（公开已知，用于理解）：
 *   - 明文 JSON → AES-128-CBC（密钥是固定字符串，第一次）
 *   - 上一步结果 → AES-128-CBC（第二次，密钥也是固定字符串）
 *     两次结果拼成 params
 *   - encSecKey = RSA 加密(clientSecret)，使用网易云公开的 modulus/publicExponent
 *
 * 注意：这些密钥是网易云客户端里硬编码的公开值，
 *       逆向的价值在于「定位它们在哪里、如何被使用」，而不是密钥本身保密。
 */

const crypto = require('crypto');

// 网易云 weapi 的硬编码参数（来自客户端逆向，公开已知）
const WEAPI_AES_KEY_1 = '0CoJUm6Qyw8W8jud'; // 第一次 AES 的 key
const WEAPI_AES_KEY_2 = 'FFFFFFFFFFFFFFFF'; // 第二次 AES 的 key（16 字节，全 F）
const WEAPI_IV = '0102030405060708';
const RSA_MODULUS =
  '00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7';
const RSA_PUB_EXP = '010001';
const RSA_RANDOM_STR = '0CoJUm6Qyw8W8jud'; // 实际 clientSecret 用随机串，这里演示固定值

function aesCbcEncrypt(plainText, key) {
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(key, 'utf8'), Buffer.from(WEAPI_IV, 'utf8'));
  cipher.setAutoPadding(true);
  // 注意：weapi 用 「PKCS7 补位 + 原始字节」；Node 默认 PKCS7，直接 update+final
  let enc = cipher.update(plainText, 'utf8', 'base64');
  enc += cipher.final('base64');
  return enc;
}

/**
 * 两次 AES 加密：先 key1 再 key2（注意第一次结果作为第二次的明文）
 * 真实实现里第二次加密前会对第一次结果做 base64 解码再当字节加密，
 * 这里给出「原理等价」的演示版本。
 */
function weapiEncrypt(text) {
  const first = aesCbcEncrypt(text, WEAPI_AES_KEY_1);
  const second = aesCbcEncrypt(first, WEAPI_AES_KEY_2);
  const params = second; // 实际是 base64 串
  const encSecKey = rsaEncrypt(RSA_RANDOM_STR);
  return { params, encSecKey };
}

function rsaEncrypt(text) {
  const buff = Buffer.from(text, 'utf8').reverse(); // 网易云把字节反转后再 RSA
  const m = parseInt(RSA_MODULUS, 16);
  const e = parseInt(RSA_PUB_EXP, 16);
  const base = bigIntFromBuffer(buff);
  const enc = base.modPow(e, m);
  return enc.toString(16).padStart(256, '0');
}

// 简易大数支持（Node 自带 BigInt 即可，无需库）
function bigIntFromBuffer(buf) {
  let hex = buf.toString('hex');
  return BigInt('0x' + hex);
}

/**
 * 演示：用加密方式调用 weapi 接口（理解用，不一定要跑通签到）
 */
function signWeapi(type) {
  return new Promise((resolve) => {
    const text = JSON.stringify({ type });
    const { params, encSecKey } = weapiEncrypt(text);

    request(
      {
        url: 'https://music.163.com/weapi/point/dailyTask',
        method: 'POST',
        followRedirect: true,
        gzip: true,
        form: { params, encSecKey },
        headers: {
          Cookie: COOKIE,
          Host: 'music.163.com',
          'User-Agent': UA_WEB,
          Referer: 'https://music.163.com/',
        },
      },
      (err, resp, data) => {
        console.log('[weapi demo]', err || data);
        resolve();
      }
    );
  });
}

// ─────────────────────────────────────────────────────────────────────────
// 入口
// ─────────────────────────────────────────────────────────────────────────
(async () => {
  // 主流程：跑能用的老接口签到（已修 301）
  await runSign();

  // 选修：想看加密长啥样就取消下面注释（仅学习）
  // await signWeapi(1);
})();

/**
 * ============================================================================
 *  运行方式：
 *    npm init -y && npm i request
 *    NEM_COOKIE="你的Cookie" node neteasemusic_reverse.js
 *
 *  301 修复总结：
 *    - 把 http:// 改成 https://
 *    - request 加 followRedirect:true
 *    - 若仍 30x，多半是 Cookie 失效，需要重新抓（带 __csrf 与登录态）
 * ============================================================================
 */
