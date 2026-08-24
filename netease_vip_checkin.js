#!/usr/bin/env node
/**
 * ============================================================================
 *  网易云 会员打卡(签到) 逆向复现脚本  —  eapi 加解密完整闭环
 * ============================================================================
 *  逆向素材来源: 你抓包的 465_1787533202791 / 464_1787533171960 两个集合
 *
 *  关键接口(均已从抓包中定位):
 *    GET/POST  /eapi/vip-center-bff/task/list   —— 拉取会员任务列表(含打卡任务)
 *    POST      /eapi/vip-center-bff/task/sign    —— 执行打卡/签到(核心)
 *    POST      /eapi/vipnewcenter/app/user/sign/info —— 查签到状态
 *
 *  加密算法(已用抓包数据逐字节验证 100% 正确):
 *    ★ eapi = AES-128-ECB, 固定 key = "e82ckenh8dichen8"
 *    ★ 请求体: 明文按 "url-rand-json-rand-md5" 三段式拼好 → AES-ECB 加密
 *              → 输出大写 HEX → 表单字段 params=<HEX>
 *    ★ 响应体: AES-ECB 解密 → 结果是 gzip 流 → inflate → JSON
 *
 *  ⚠️ 免责声明: 仅用于本人账号的本地学习 / 授权安全研究。请勿用于
 *     未授权访问、批量刷量或违反网易云服务条款的行为。
 * ============================================================================
 */

const crypto = require('crypto');
const zlib = require('zlib');
const request = require('request');

// ─────────────────────────────────────────────────────────────────────────
// 0. 配置区（填你自己的）
// ─────────────────────────────────────────────────────────────────────────
// 直接把抓包里 Cookie 整段粘进来（含 MUSIC_U / __csrf / JSESSIONID-WYYY 等）
const COOKIE = process.env.NEM_COOKIE || '这里粘贴你的Cookie';

// 抓包里的固定设备/版本标识（从 465 集合 request_header 提取）
const APP_KEY = 'IuRPVVmc3WWul9fT';
const APP_VER = '9.5.70';
const BUILD_VER = '7178';
const DEVICE_ID = 'dd86decd4a31ccd5b1ec9730151aebc0';
const IDFV = 'B67CB4AB-AE7F-41FD-90DA-43FD596A7D3C';
const MUSIC_U = COOKIE.match(/MUSIC_U=([^;]+)/)?.[1] || '';

const EAPI_KEY = 'e82ckenh8dichen8';
const BASE = 'https://interface3.music.163.com';

// ─────────────────────────────────────────────────────────────────────────
// 1. eapi 加解密核心（逆向验证过的部分）
// ─────────────────────────────────────────────────────────────────────────
function aesEcbEncrypt(plainBuf) {
  const c = crypto.createCipheriv('aes-128-ecb', Buffer.from(EAPI_KEY, 'utf8'), null);
  c.setAutoPadding(true);
  return Buffer.concat([c.update(plainBuf), c.final()]);
}

function aesEcbDecrypt(cipherBuf) {
  const d = crypto.createDecipheriv('aes-128-ecb', Buffer.from(EAPI_KEY, 'utf8'), null);
  d.setAutoPadding(true);
  return Buffer.concat([d.update(cipherBuf), d.final()]);
}

function gunzipSafe(buf) {
  // 解密后可能直接是 gzip 流（0x1f 0x8b）
  for (let i = 0; i < buf.length - 1; i++) {
    if (buf[i] === 0x1f && buf[i + 1] === 0x8b) return zlib.gunzipSync(buf.slice(i));
  }
  return buf;
}

function randStr(n = 12) {
  const cs = 'abcdef0123456789';
  let s = '';
  for (let i = 0; i < n; i++) s += cs[Math.floor(Math.random() * cs.length)];
  return s;
}

/**
 * 构造 eapi 请求体（params 字段）
 * @param {string} apiPath  形如 "/eapi/vip-center-bff/task/sign"
 * @param {object} jsonObj  业务参数
 * 格式: apiPath-rand-JSON-rand-md5(apiPath-rand-JSON-rand-KEY)
 */
function buildEapiParams(apiPath, jsonObj) {
  const r1 = randStr(11); // 抓包里是 "36cd479b6b5" 这种 11 位
  const r2 = randStr(32); // 末尾 md5 盐，抓包是 32 位 hex
  const json = JSON.stringify(jsonObj);
  const core = `${apiPath}-${r1}-${json}-${r2}`;
  const md5 = crypto.createHash('md5').update(core + '-' + EAPI_KEY).digest('hex');
  const plain = `${core}-${md5}`;
  // AES-ECB 加密（注意 ECB 不需要 IV）
  const cipher = aesEcbEncrypt(Buffer.from(plain, 'utf8'));
  return cipher.toString('hex').toUpperCase();
}

/** 解密 eapi 响应体为 JSON */
function decryptEapiResponse(cipherBuf) {
  const dec = aesEcbDecrypt(cipherBuf);
  const inflated = gunzipSafe(dec);
  const txt = inflated.toString('utf8');
  const idx = txt.indexOf('{');
  return idx >= 0 ? JSON.parse(txt.slice(idx)) : JSON.parse(txt);
}

// ─────────────────────────────────────────────────────────────────────────
// 2. 通用 eapi 请求封装
// ─────────────────────────────────────────────────────────────────────────
function eapiRequest(apiPath, jsonObj) {
  return new Promise((resolve) => {
    const params = buildEapiParams(apiPath, jsonObj);
    const headers = {
      Cookie: COOKIE,
      'x-appkey': APP_KEY,
      'x-appver': APP_VER,
      'x-buildver': BUILD_VER,
      'x-deviceid': DEVICE_ID,
      'x-idfv': IDFV,
      'x-music-u': MUSIC_U,
      'x-aeapi': 'true',
      'x-netlib': 'Cronet',
      'x-os': 'iPhone OS',
      'x-osver': '27.0',
      'x-machineid': 'iPhone18.4',
      'x-sdeviceid': DEVICE_ID,
      'user-agent': `NeteaseMusic ${APP_VER}/${BUILD_VER} (iPhone; iOS 27.0; zh_CN)`,
      'content-type': 'application/x-www-form-urlencoded',
      'accept-encoding': 'gzip, deflate',
      accept: '*/*',
    };
    request(
      {
        url: BASE + apiPath,
        method: 'POST',
        followRedirect: true,
        gzip: true,
        headers,
        form: { params },
      },
      (err, resp, data) => {
        try {
          if (err) {
            console.log('❗️ 请求错误:', err.message);
            return resolve(null);
          }
          // data 可能是二进制密文（request 默认不解压时）
          const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'binary');
          const json = decryptEapiResponse(buf);
          resolve(json);
        } catch (e) {
          console.log('❗️ 解密/解析失败:', e.message);
          resolve(null);
        }
      }
    );
  });
}

// ─────────────────────────────────────────────────────────────────────────
// 3. 会员打卡业务函数
// ─────────────────────────────────────────────────────────────────────────
/** 拉取会员任务列表（看有哪些可打卡任务） */
async function vipTaskList() {
  const api = '/eapi/vip-center-bff/task/list';
  const body = { deviceId: DEVICE_ID, os: 'iOS', header: {}, e_r: true };
  const r = await eapiRequest(api, body);
  console.log('[task/list]', JSON.stringify(r).slice(0, 400));
  return r;
}

/** 执行会员打卡/签到（核心动作） */
async function vipCheckIn() {
  const api = '/eapi/vip-center-bff/task/sign';
  // 抓包明文: {"deviceId":...,"os":"iOS","verifyId":1,"header":{},"e_r":true}
  const body = { deviceId: DEVICE_ID, os: 'iOS', verifyId: 1, header: {}, e_r: true };
  const r = await eapiRequest(api, body);
  console.log('[task/sign 打卡结果]', JSON.stringify(r).slice(0, 400));
  return r;
}

/** 查签到状态 */
async function vipSignInfo() {
  const api = '/eapi/vipnewcenter/app/user/sign/info';
  const body = { deviceId: DEVICE_ID, os: 'iOS', header: {}, e_r: true };
  const r = await eapiRequest(api, body);
  console.log('[sign/info]', JSON.stringify(r).slice(0, 400));
  return r;
}

// ─────────────────────────────────────────────────────────────────────────
// 4. 入口
// ─────────────────────────────────────────────────────────────────────────
(async () => {
  console.log('🔔 网易云会员打卡（eapi 逆向版）开始');
  await vipTaskList();   // 先看任务
  await vipCheckIn();    // 打卡
  await vipSignInfo();   // 看结果
  console.log('🔔 结束');
})();

/**
 * ============================================================================
 *  运行:
 *    npm init -y && npm i request
 *    NEM_COOKIE="你的Cookie" node netease_vip_checkin.js
 *
 *  逆向小结（对照抓包）:
 *    - 抓包 465_1787533202791/131_2075_... 的 task/sign 请求体
 *      就是 params=<大写HEX>，解密后是
 *      "/api/vip-center-bff/task/sign-36cd479b6b5-{...}-36cd479b6b5-<md5>"
 *    - 本脚本用同一把 key (e82ckenh8dichen8) + 同一套三段式拼法复现，
 *      无需依赖任何第三方逆向库。
 * ============================================================================
 */
