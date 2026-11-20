/**
 * 邮百工（北邮）模型网关 —— magpie / OpenCode 供应商插件
 *
 * 一个 npm 包、一个 Bun 模块。magpie 把它的模型当成普通供应商：agent 用
 * baigong/<model> 就能用，多账号、故障切换、用量都跟着走。
 *
 * 学号密码 → 令牌全程直连 HTTP，不打开浏览器：
 *   ① POST {edugate}/local-auth/start      PKCE(S256) → request_id
 *   ② GET  {cas}/authserver/login?service=…/cas-callback → execution（CAS 表单，不加密密码）
 *   ③ POST 同一地址 {username, password, execution, …} → 302 …/cas-callback?ticket=ST-…
 *   ④ 跟随 302 → {web}?cas_login=success&token=…
 *   ⑤ POST {edugate}/local-auth/complete {request_id, provider:"bupt_cas", token} → local_redirect_url(code)
 *   ⑥ POST {edugate}/local-auth/exchange → access_token / refresh_token
 *   ⑦ GET  {edugate}/local-auth/runtime-config → HKDF+AES-GCM 信封 → { apiBase, apiKey, models[] }
 * 平台自建账号走另一条：POST {edugate}/login {username, password, local_request_id}，其余步骤相同。
 *
 * 模型：纯文本 + 思考 + 工具调用，不声明图像能力；请求里夹带的图片在 fetch 层丢掉
 * （上游一次只收 1 张图，而且本模型本来就不给识图）。
 *
 * 计价：模型 cost 写**谷价**（高峰 = 谷价 ×2），供应商级 rateWindows 声明高峰时段，
 * magpie 按调用时刻计价。magpie 不认识这个字段时它被忽略，退化成固定谷价，不影响请求。
 */

import { createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { createServer } from "node:net";

const EDUGATE = "https://baigongai.cn/edugate/api";
const CAS_URL = "https://auth.bupt.edu.cn";
const WEB_URL = "https://baigongai.cn";
const DEFAULT_BASE_URL = "https://gateway.baigongai.cn/v1";
const PROVIDER = "baigong";
const CALLBACK_PATH = "/ybg-auth/callback";
const RUNTIME_INFO = "youlabber-local-runtime-config-v1";
const SESSION_HEADER = "youlabber-local-pc";
const BROWSER_UA =
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const REQUEST_TIMEOUT_MS = 30_000;
const CONTEXT_WINDOW = 262_144;
const MAX_OUTPUT_TOKENS = 32_768;
const ACCESS_FALLBACK_MS = 2 * 60 * 60_000;
/** 静默重登的冷却：密码错了就别每个刷新周期都去打一次统一认证（会被风控/锁号）。 */
const RELOGIN_COOLDOWN_MS = 10 * 60_000;
let lastReloginAt = 0;

// ---------------------------------------------------------------- 小工具

/** 谷价：高峰刊例价的一半（DeepSeek 官方峰谷是 2 倍关系）。 */
const COST_FLASH = { input: 0.15, output: 0.6, cache_read: 0.003, cache_write: 0 };
const COST_PRO = { input: 0.66, output: 1.98, cache_read: 0.022, cache_write: 0 };

const THINKING_VARIANTS = { low: {}, high: {}, xhigh: {}, max: {} };

/** 北京时间高峰：08:30–24:00 与 00:00–00:30；谷时 00:30–08:30 不打折。 */
const PEAK_WINDOWS = [
	{ days: [], start: "08:30", end: "24:00", rate: 2 },
	{ days: [], start: "00:00", end: "00:30", rate: 2 },
];

function b64url(buffer) {
	return buffer.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function createPkce() {
	const verifier = b64url(randomBytes(32));
	const challenge = b64url(createHash("sha256").update(verifier).digest());
	const state = b64url(randomBytes(16));
	return { verifier, challenge, state };
}

/** 一个空闲的回环端口当 redirect_uri：不监听，只要求 start 与 exchange 两次一致。 */
function loopbackRedirectUri() {
	return new Promise((resolve, reject) => {
		const server = createServer();
		server.on("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const { port } = server.address();
			server.close(() => resolve(`http://127.0.0.1:${port}${CALLBACK_PATH}`));
		});
	});
}

async function readJson(response) {
	const text = await response.text();
	if (text.trim() === "") return {};
	try {
		return JSON.parse(text);
	} catch {
		return { message: text.slice(0, 200) };
	}
}

function detailOf(payload) {
	return typeof payload?.message === "string" && payload.message !== "" ? `：${payload.message}` : "";
}

/** access_expires_at 可能是秒、毫秒或 ISO；都归一成毫秒。 */
function parseExpiry(value, fallbackMs) {
	if (typeof value === "number" && Number.isFinite(value)) return value < 1e12 ? value * 1000 : value;
	if (typeof value === "string" && value !== "") {
		const asNumber = Number(value);
		if (Number.isFinite(asNumber) && asNumber > 0) return asNumber < 1e12 ? asNumber * 1000 : asNumber;
		const parsed = Date.parse(value);
		if (Number.isFinite(parsed)) return parsed;
	}
	return Date.now() + fallbackMs;
}

function maskUsername(username) {
	const text = String(username ?? "");
	return text.length <= 4 ? `${text.slice(0, 1)}***` : `${text.slice(0, 4)}***`;
}

// ---------------------------------------------------------------- 网关接口

async function startLocalAuth(pkce, redirectUri, deviceName) {
	const response = await fetch(`${EDUGATE}/local-auth/start`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			state: pkce.state,
			code_challenge: pkce.challenge,
			code_challenge_method: "S256",
			redirect_uri: redirectUri,
			device_name: deviceName || "magpie",
		}),
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	const payload = await readJson(response);
	const requestId = payload?.data?.request_id;
	if (!response.ok || typeof requestId !== "string" || requestId === "") {
		throw new Error(`无法开始登录：HTTP ${response.status}${detailOf(payload)}`);
	}
	return requestId;
}

async function completeLocalAuth({ requestId, provider, token, cookie }) {
	const headers = { "Content-Type": "application/json" };
	if (cookie) headers.Cookie = cookie;
	const response = await fetch(`${EDUGATE}/local-auth/complete`, {
		method: "POST",
		headers,
		body: JSON.stringify({ request_id: requestId, provider, token }),
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	const payload = await readJson(response);
	const localRedirect = payload?.data?.local_redirect_url;
	if (!response.ok || typeof localRedirect !== "string" || localRedirect === "") {
		throw new Error(`换取本机登录码失败：HTTP ${response.status}${detailOf(payload)}`);
	}
	return localRedirect;
}

async function exchangeLocalAuth(code, pkce, redirectUri) {
	const response = await fetch(`${EDUGATE}/local-auth/exchange`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ code, code_verifier: pkce.verifier, redirect_uri: redirectUri }),
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	const payload = await readJson(response);
	const data = payload?.data;
	if (!response.ok || typeof data?.access_token !== "string" || data.access_token === "") {
		throw new Error(`换取令牌失败：HTTP ${response.status}${detailOf(payload)}`);
	}
	if (typeof data.refresh_token !== "string" || data.refresh_token === "") {
		throw new Error("换取令牌失败：响应里没有 refresh_token。");
	}
	return data;
}

function codeFromLocalRedirect(localRedirect, state) {
	let redirect;
	try {
		redirect = new URL(localRedirect);
	} catch {
		throw new Error("本机回跳地址格式不对。");
	}
	const gotState = redirect.searchParams.get("state");
	if (gotState !== null && gotState !== "" && gotState !== state) throw new Error("登录失败：回跳 state 不匹配。");
	const code = redirect.searchParams.get("code");
	if (code === null || code === "") throw new Error("登录失败：回跳地址里没有登录码。");
	return code;
}

/** runtime-config：HKDF(access) 派生密钥，解 AES-256-GCM 信封。 */
let runtimeCache;

function decodeEnvelope(accessToken, envelope) {
	const salt = typeof envelope?.salt === "string" ? Buffer.from(envelope.salt, "base64") : undefined;
	const nonce = typeof envelope?.nonce === "string" ? Buffer.from(envelope.nonce, "base64") : undefined;
	const ciphertext = typeof envelope?.ciphertext === "string" ? Buffer.from(envelope.ciphertext, "base64") : undefined;
	if (!salt || !nonce || !ciphertext || nonce.length !== 12 || ciphertext.length < 17) {
		throw new Error("运行配置信封格式不正确");
	}
	const key = Buffer.from(hkdfSync("sha256", Buffer.from(accessToken), salt, Buffer.from(RUNTIME_INFO), 32));
	const decipher = createDecipheriv("aes-256-gcm", key, nonce);
	decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
	const plain = Buffer.concat([
		decipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
		decipher.final(),
	]);
	const parsed = JSON.parse(plain.toString("utf8"));
	if (typeof parsed?.apiKey !== "string" || parsed.apiKey === "") throw new Error("运行配置里没有网关 Key");
	return {
		apiBase: typeof parsed.apiBase === "string" && parsed.apiBase.trim() !== "" ? parsed.apiBase.trim() : DEFAULT_BASE_URL,
		apiKey: parsed.apiKey,
		defaultModel: parsed.defaultModel,
		models: Array.isArray(parsed.models)
			? parsed.models.filter((model) => typeof model?.id === "string" && model.id !== "")
			: [],
	};
}

async function fetchRuntimeConfig(accessToken, force = false) {
	if (!force && runtimeCache && runtimeCache.token === accessToken && Date.now() - runtimeCache.at < 60_000) {
		return runtimeCache.value;
	}
	const response = await fetch(`${EDUGATE}/local-auth/runtime-config`, {
		headers: { Authorization: `Bearer ${accessToken}` },
		cache: "no-store",
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	const payload = await readJson(response);
	if (!response.ok) throw new Error(`取运行配置失败：HTTP ${response.status}${detailOf(payload)}`);
	const envelope = payload?.data;
	if (typeof envelope !== "object" || envelope === null || envelope.version !== 1) {
		throw new Error("响应里没有 version 1 的运行配置信封");
	}
	const value = decodeEnvelope(accessToken, envelope);
	runtimeCache = { token: accessToken, at: Date.now(), value };
	return value;
}

async function tryFetchRuntimeConfig(accessToken, force = false) {
	try {
		return await fetchRuntimeConfig(accessToken, force);
	} catch {
		return undefined;
	}
}

function credentialsFrom(tokens, runtime, extra) {
	return {
		type: "oauth",
		access: tokens.access_token,
		refresh: tokens.refresh_token,
		expires: parseExpiry(tokens.access_expires_at, ACCESS_FALLBACK_MS),
		apiKey: runtime?.apiKey,
		apiBase: runtime?.apiBase,
		identity: tokens.identity,
		...extra,
	};
}

// ---------------------------------------------------------------- 无头登录

const CAS_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9";

/** 按域名分桶的极简 cookie jar（CAS 与站点之间要来回带）。 */
class CookieJar {
	constructor() {
		this.buckets = new Map();
	}

	absorb(hostname, response) {
		const lines = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
		for (const line of lines) {
			const [pair, ...attributes] = line.split(";");
			const eq = pair.indexOf("=");
			if (eq <= 0) continue;
			let domain = hostname.toLowerCase();
			for (const attribute of attributes) {
				const [key, raw = ""] = attribute.split("=");
				if (key.trim().toLowerCase() === "domain" && raw.trim() !== "") {
					domain = raw.trim().replace(/^\./, "").toLowerCase();
				}
			}
			const bucket = this.buckets.get(domain) ?? new Map();
			bucket.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
			this.buckets.set(domain, bucket);
		}
	}

	header(hostname) {
		const host = hostname.toLowerCase();
		const parts = [];
		for (const [domain, bucket] of this.buckets) {
			if (host === domain || host.endsWith(`.${domain}`)) {
				for (const [name, value] of bucket) parts.push(`${name}=${value}`);
			}
		}
		return parts.join("; ");
	}
}

async function casRequest(url, init, jar) {
	const headers = {
		"User-Agent": BROWSER_UA,
		"Accept-Language": CAS_ACCEPT_LANGUAGE,
		...(init.headers ?? {}),
	};
	const cookie = jar.header(new URL(url).hostname);
	if (cookie !== "") headers.Cookie = cookie;
	const response = await fetch(url, {
		...init,
		headers,
		redirect: "manual",
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	jar.absorb(new URL(url).hostname, response);
	return {
		status: response.status,
		ok: response.ok,
		location: response.headers.get("location") ?? undefined,
		body: await response.text(),
	};
}

function decodeEntities(value) {
	return value
		.replaceAll("&amp;", "&")
		.replaceAll("&quot;", '"')
		.replaceAll("&#39;", "'")
		.replaceAll("&lt;", "<")
		.replaceAll("&gt;", ">");
}

function formFields(html) {
	const fields = {};
	for (const match of html.matchAll(/<input\b[^>]*>/gi)) {
		const tag = match[0];
		const name = /\bname="([^"]*)"/i.exec(tag)?.[1] ?? "";
		if (name === "") continue;
		const type = (/\btype="([^"]*)"/i.exec(tag)?.[1] ?? "text").toLowerCase();
		const value = decodeEntities(/\bvalue="([^"]*)"/i.exec(tag)?.[1] ?? "");
		if (type === "hidden" || name === "execution" || name === "type" || name === "_eventId" || name === "lt") {
			fields[name] = value;
		}
	}
	return fields;
}

function casFailure(html) {
	const captcha = /name="captcha"|id="captcha"/i.test(html);
	const patterns = [
		/<span[^>]*id="msg"[^>]*>([\s\S]*?)<\/span>/i,
		/<div[^>]*class="[^"]*(?:alert|error|errors|auth_error)[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
		/<p[^>]*class="[^"]*(?:error|alert)[^"]*"[^>]*>([\s\S]*?)<\/p>/i,
	];
	for (const pattern of patterns) {
		const match = pattern.exec(html);
		if (match === null) continue;
		const text = decodeEntities(match[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
		if (text !== "") return { message: text, captcha };
	}
	return { message: "", captcha };
}

function successParams(url) {
	let parsed;
	try {
		parsed = new URL(url);
	} catch {
		return undefined;
	}
	const flag = parsed.searchParams.get("cas_login");
	if (flag === null) return undefined;
	if (flag !== "success") throw new Error(`北邮统一认证返回失败：${flag}`);
	if (parsed.searchParams.get("token") === null) return undefined;
	return parsed.searchParams;
}

async function followToToken(start, from, jar) {
	let next = start;
	let current = from;
	for (let hop = 0; hop < 10 && next !== undefined; hop++) {
		const absolute = new URL(next, current).href;
		const params = successParams(absolute);
		if (params !== undefined) return params;
		const response = await casRequest(absolute, {}, jar);
		if (response.location === undefined) {
			throw new Error(`北邮统一认证没有回到站点（HTTP ${response.status}）。`);
		}
		next = response.location;
		current = absolute;
	}
	throw new Error("北邮统一认证跳转次数过多。");
}

/** 北邮统一认证（CAS）。返回令牌 + 运行配置。 */
async function casLogin(username, password, onProgress) {
	const pkce = createPkce();
	const redirectUri = await loopbackRedirectUri();
	const jar = new CookieJar();
	const service = `${EDUGATE}/cas-callback`;
	const loginUrl = `${CAS_URL}/authserver/login?service=${encodeURIComponent(service)}`;

	onProgress?.(`正在用学号 ${maskUsername(username)} 登录北邮统一认证（不打开浏览器）…`);
	const requestId = await startLocalAuth(pkce, redirectUri, "magpie");

	const page = await casRequest(loginUrl, {}, jar);
	if (!page.ok) throw new Error(`北邮统一认证页面打不开：HTTP ${page.status}`);
	if (!/<input\b[^>]*name="username"/i.test(page.body)) {
		throw new Error("北邮统一认证页面里没有登录表单（可能被风控拦截，或页面结构变了）。");
	}
	const fields = formFields(page.body);
	if (fields.execution === undefined || fields.execution === "") {
		throw new Error("北邮统一认证页面结构变了：没找到 execution 字段。");
	}

	const form = new URLSearchParams({ ...fields, username, password, submit: "LOGIN" });
	const post = await casRequest(
		loginUrl,
		{
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Referer: loginUrl,
				Origin: CAS_URL,
			},
			body: form.toString(),
		},
		jar,
	);
	if (post.location === undefined) {
		const { message, captcha } = casFailure(post.body);
		if (captcha) throw new Error("北邮统一认证要求输入验证码，无法无头登录。");
		throw new Error(message !== "" ? `北邮统一认证登录失败：${message}` : "北邮统一认证登录失败：学号或密码可能不对。");
	}

	const params = await followToToken(post.location, loginUrl, jar);
	const token = params.get("token") ?? "";
	if (token === "") throw new Error("北邮统一认证成功，但没有拿到换本机令牌所需的 token。");

	onProgress?.("统一认证通过，正在换取本机令牌…");
	const localRedirect = await completeLocalAuth({
		requestId,
		provider: "bupt_cas",
		token,
		cookie: jar.header(new URL(EDUGATE).hostname),
	});
	const code = codeFromLocalRedirect(localRedirect, pkce.state);
	const tokens = await exchangeLocalAuth(code, pkce, redirectUri);
	const runtime = await fetchRuntimeConfig(tokens.access_token, true);
	return credentialsFrom(tokens, runtime, { loginMode: "password", loginProvider: "bupt_cas" });
}

/** 平台自建账号（登录页的「校园账号登录」）。 */
async function platformLogin(username, password, onProgress) {
	const pkce = createPkce();
	const redirectUri = await loopbackRedirectUri();

	onProgress?.(`正在用学号 ${maskUsername(username)} 登录校园账号（不打开浏览器）…`);
	const requestId = await startLocalAuth(pkce, redirectUri, "magpie");

	const response = await fetch(`${EDUGATE}/login`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ username, password, local_request_id: requestId }),
		signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
	});
	const payload = await readJson(response);
	if (!response.ok) {
		throw new Error(`校园账号登录失败：${detailOf(payload).replace(/^：/, "") || `HTTP ${response.status}`}`);
	}
	const data = payload?.data;
	if (typeof data?.local_error === "string" && data.local_error !== "") {
		throw new Error(`校园账号登录失败：${data.local_error}`);
	}
	const localRedirect = typeof data?.local_redirect_url === "string" ? data.local_redirect_url : "";
	const code = codeFromLocalRedirect(localRedirect, pkce.state);
	onProgress?.("已通过密码校验，正在换取令牌…");
	const tokens = await exchangeLocalAuth(code, pkce, redirectUri);
	const runtime = await fetchRuntimeConfig(tokens.access_token, true);
	return credentialsFrom(tokens, runtime, { loginMode: "password", loginProvider: "platform" });
}

/**
 * 两条路自动选：北邮统一认证优先，失败再试平台账号（两者凭据不通用）。
 * 两条都失败时，把两条的原因一起抛出来，免得只看到一半。
 */
async function loginAny(username, password, onProgress) {
	try {
		return await casLogin(username, password, onProgress);
	} catch (casError) {
		try {
			return await platformLogin(username, password, onProgress);
		} catch (platformError) {
			throw new Error(`${casError.message}；校园账号登录也不行：${platformError.message}`);
		}
	}
}

// ---------------------------------------------------------------- 请求改写

/**
 * 上游 vLLM 一次请求（含历史）只收 1 张图，多一张就 400：
 *   At most 1 image(s) may be provided in one prompt.
 * magpie 的供应商字段 max-images=1 已经会做同样的事（保留最新的、更早的换成一行文字），
 * 这里再兜一层，免得那个字段没设上时被上游拒掉。keep=0 就是一张都不发。
 */
const IMAGES_PER_REQUEST = 1;

function dropImages(body, keep = IMAGES_PER_REQUEST) {
	const images = [];
	for (const message of body.messages ?? []) {
		if (!Array.isArray(message?.content)) continue;
		for (const part of message.content) {
			const type = typeof part?.type === "string" ? part.type : "";
			if (type === "image_url" || type === "input_image" || type === "image") images.push(part);
		}
	}
	// 最新的留在后面：只丢最早的，直到剩下 keep 张
	const drop = new Set(images.slice(0, Math.max(0, images.length - keep)));
	if (drop.size === 0) return 0;
	for (const message of body.messages ?? []) {
		if (!Array.isArray(message?.content)) continue;
		const kept = [];
		let removed = 0;
		for (const part of message.content) {
			if (drop.has(part)) {
				removed += 1;
				continue;
			}
			kept.push(part);
		}
		if (removed > 0) {
			kept.push({ type: "text", text: `[已省略 ${removed} 张较早的图片：该模型每次请求只收 1 张]` });
			message.content = kept;
		}
	}
	return drop.size;
}

// ---------------------------------------------------------------- 插件本体

/**
 * @param {{ magpie?: { options?: object, option?: object }, client?: any }} input
 */
async function baigongPlugin(input) {
	const deviceName = typeof process.env.HOSTNAME === "string" ? process.env.HOSTNAME : "magpie";
	const options = input?.magpie?.options ?? input?.magpie?.option ?? {};

	const ready = (auth) => {
		const baseURL = auth?.apiBase || DEFAULT_BASE_URL;
		const apiKey = auth?.apiKey;
		return { baseURL, apiKey, headers: { "X-YBG-Session-ID": SESSION_HEADER } };
	};

	return {
		// 供应商、模型、计价
		config: async (cfg) => {
			cfg.provider ??= {};
			cfg.provider[PROVIDER] ??= {
				name: "邮百工（北邮）",
				npm: "@ai-sdk/openai-compatible", // chat completions
				api: DEFAULT_BASE_URL,
				// 上下文、最大输出、图片限额都由模型的 limit 决定（下面每个模型都写了），
				// 所以不在这里重复声明 —— magpie 也不会采纳插件写的供应商级字段。
				// 想让它出现在编辑页「高级」里，用户设一次即可：
				//   magpie provider set baigong context=256k max-images=1
				//
				// 峰谷：这里是给宿主留的意图声明（谷价 ×2 的高峰窗口）。magpie 目前不采纳
				// 插件写的 rateWindows，要精确计峰谷就在编辑页「Rate windows」加两条。
				rateWindows: PEAK_WINDOWS,
				models: {
					"ybg-youlaber-ds4f": {
						name: "百工 Flash (DeepSeek V4.1 Flash)",
						limit: { context: CONTEXT_WINDOW, output: MAX_OUTPUT_TOKENS },
						reasoning: true,
						tool_call: true,
						// 接受图像：magpie 的 max-images=1 会只留最新一张，插件里也兜一层
						modalities: { input: ["text", "image"] },
						cost: COST_FLASH,
						variants: THINKING_VARIANTS,
					},
					"ybg-youlaber-ds4pro": {
						name: "百工 Pro (DeepSeek V4 Pro)",
						limit: { context: CONTEXT_WINDOW, output: MAX_OUTPUT_TOKENS },
						reasoning: true,
						tool_call: true,
						modalities: { input: ["text", "image"] },
						cost: COST_PRO,
						variants: THINKING_VARIANTS,
					},
				},
			};
		},

		// 登录：学号 + 密码（应用里是掩码输入框），全在 HTTP 里完成，不开浏览器
		auth: {
			provider: PROVIDER,
			methods: [
				{
					type: "oauth",
					label: "邮百工（北邮）学号密码",
					prompts: [
						{ type: "text", key: "username", message: "学号 / 校园账号", placeholder: "2023xxxxxx" },
						{ type: "password", key: "password", message: "密码", placeholder: "统一认证密码" },
					],
					/**
					 * 不需要浏览器，所以 authorize 只交回一个「登录会话」：告诉 magpie 没有要打开的
					 * 页面，真正的登录放在 callback 里一次做完（magpie 对 method "auto" 会直接调它）。
					 */
					async authorize(inputs) {
						const username = String(inputs?.username ?? options.username ?? "").trim();
						const password = String(inputs?.password ?? options.password ?? "");
						if (username === "" || password === "") {
							return { type: "failed", error: "需要学号和密码。" };
						}
						return {
							url: "",
							instructions: `用学号 ${maskUsername(username)} 直连北邮统一认证，不需要浏览器…`,
							method: "auto",
							async callback(_code, { signal } = {}) {
								try {
									const credentials = await loginAny(username, password);
									if (signal?.aborted) return { type: "failed", error: "登录已取消。" };
									const identity = credentials.identity ?? {};
									return {
										type: "success",
										refresh: credentials.refresh,
										access: credentials.access,
										expires: credentials.expires,
										apiKey: credentials.apiKey,
										apiBase: credentials.apiBase,
										identity,
										loginProvider: credentials.loginProvider,
										// 存进账号：refresh 过期时用来自动重登，也用来在界面上认人
										username,
										password,
										accountId:
											typeof identity.student_number === "string" && identity.student_number !== ""
												? identity.student_number
												: username,
									};
								} catch (error) {
									return { type: "failed", error: String(error?.message ?? error).slice(0, 500) };
								}
							},
						};
					},
				},
			],

			// 续期：refresh_token 换新 access（网关 Key 由 access 派生，要重新取配置）
			async refresh(auth) {
				const rejected = (error) => {
					const message = String(error?.message ?? error);
					const fatal = /HTTP (400|401|403|422)/.test(message);
					return Object.assign(new Error(message), { signIn: fatal ? "expired" : undefined });
				};

				let next;
				try {
					const response = await fetch(`${EDUGATE}/local-auth/refresh`, {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ refresh_token: auth.refresh }),
						signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
					});
					const payload = await readJson(response);
					if (!response.ok || typeof payload?.data?.access_token !== "string") {
						throw new Error(`刷新失败：HTTP ${response.status}${detailOf(payload)}`);
					}
					const data = payload.data;
					next = {
						access: data.access_token,
						refresh:
							typeof data.refresh_token === "string" && data.refresh_token !== ""
								? data.refresh_token
								: auth.refresh,
						expires: parseExpiry(data.access_expires_at, ACCESS_FALLBACK_MS),
						identity: data.identity ?? auth.identity,
					};
				} catch (error) {
					// 手上还有学号密码就静默重登一次；失败才算登录过期
					if (typeof auth.username !== "string" || typeof auth.password !== "string") {
						throw rejected(error);
					}
					const since = Date.now() - lastReloginAt;
					if (lastReloginAt !== 0 && since < RELOGIN_COOLDOWN_MS) {
						throw rejected(
							new Error(
								`${String(error?.message ?? error)}；${Math.ceil((RELOGIN_COOLDOWN_MS - since) / 60_000)} 分钟内已自动重登过，先不重试`,
							),
						);
					}
					lastReloginAt = Date.now();
					try {
						const again = await loginAny(auth.username, auth.password);
						return {
							access: again.access,
							refresh: again.refresh,
							expires: again.expires,
							apiKey: again.apiKey,
							apiBase: again.apiBase,
							identity: again.identity ?? auth.identity,
						};
					} catch (relogin) {
						throw rejected(new Error(`${String(error?.message ?? error)}；用存下的学号密码重登也失败：${String(relogin?.message ?? relogin)}`));
					}
				}

				const runtime = await tryFetchRuntimeConfig(next.access, true);
				return {
					...next,
					// 取配置失败时把到期时间压到 10 分钟后，让 magpie 很快再来一次
					expires: runtime === undefined ? Date.now() + 10 * 60_000 : next.expires,
					apiKey: runtime?.apiKey ?? auth.apiKey,
					apiBase: runtime?.apiBase ?? auth.apiBase,
				};
			},

			// 余额 / 额度：magpie 的账号卡片、额度环、余额卡、magpie quota 都读这里
			async usage(getAuth) {
				const auth = await getAuth();
				const response = await fetch(`${EDUGATE}/local-auth/token-usage`, {
					headers: { Authorization: `Bearer ${auth?.access}` },
					cache: "no-store",
					signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
				});
				const payload = await readJson(response);
				if (!response.ok) {
					const expired = response.status === 401 || response.status === 403;
					return {
						error: `额度查询失败：HTTP ${response.status}${detailOf(payload)}`,
						windows: [],
						signIn: expired ? "expired" : "kept",
					};
				}
				const data = payload?.data ?? {};
				const grant = Number(data.tokenGrant);
				const balance = Number(data.tokenBalance);
				const windows = [];
				if (Number.isFinite(grant) && grant > 0 && Number.isFinite(balance)) {
					const used = Math.max(0, grant - balance);
					windows.push({
						name: "套餐额度",
						amount: used,
						limit: grant,
						unit: "tokens",
						display: `${formatCount(used)} / ${formatCount(grant)}`,
					});
				}
				if (Number.isFinite(balance)) {
					windows.push({
						name: "余额",
						balance,
						unit: "tokens",
						display: `${formatCount(balance)} tokens`,
					});
				}
				const identity = auth?.identity ?? {};
				const who =
					typeof identity.name === "string" && typeof identity.student_number === "string"
						? `${identity.name}（${identity.student_number}）`
						: auth?.username;
				const until =
					typeof data.endDate === "string" && !data.endDate.startsWith("0001") ? data.endDate : undefined;
				return {
					plan: typeof data.planName === "string" ? data.planName : undefined,
					user: who,
					until,
					balance: Number.isFinite(balance) ? `${formatCount(balance)} tokens` : undefined,
					windows,
					signIn: "kept",
				};
			},

			// 每个账号一个 loader：请求发到哪、带什么头、怎么改请求体
			async loader(getAuth) {
				const auth = await getAuth();
				const { baseURL, apiKey, headers } = ready(auth);
				return {
					baseURL,
					apiKey,
					headers,
					async fetch(request, init) {
						const outgoing = { ...init, headers: new Headers(init?.headers) };
						outgoing.headers.set("X-YBG-Session-ID", SESSION_HEADER);
						if (typeof init?.body === "string" && init.body !== "") {
							try {
								const body = JSON.parse(init.body);
								const dropped = dropImages(body);
								if (dropped > 0) {
									outgoing.body = JSON.stringify(body);
									outgoing.headers.delete("content-length");
									outgoing.headers.delete("content-encoding");
								}
							} catch {
								// 不是 JSON 就原样发
							}
						}
						return fetch(request, outgoing);
					},
				};
			},
		},

		// 这个账号有哪些模型：静态目录 + 云端 runtime-config 里的新模型
		provider: {
			id: PROVIDER,
			async models(provider, { auth } = {}) {
				const list = { ...(provider?.models ?? {}) };
				if (typeof auth?.access !== "string") return list;
				const runtime = await tryFetchRuntimeConfig(auth.access);
				if (runtime === undefined) return list;
				// runtime 里冒出来的新模型，先照 Flash 的形状（limit / 思考 / 计价）复制一份
				const template = list["ybg-youlaber-ds4f"] ?? {
					limit: { context: CONTEXT_WINDOW, output: MAX_OUTPUT_TOKENS },
					reasoning: true,
					tool_call: true,
					modalities: { input: ["text", "image"] },
					cost: COST_FLASH,
					variants: THINKING_VARIANTS,
				};
				for (const entry of runtime.models) {
					if (list[entry.id] !== undefined) continue;
					list[entry.id] = {
						...(template ?? {}),
						id: entry.id,
						name: entry.name ?? entry.id,
						// 新模型按「文本 + 图像 + 思考」处理，价格猜不到就按 Flash 的谷价
						modalities: { input: ["text", "image"] },
						cost: /pro/i.test(entry.id) ? COST_PRO : COST_FLASH,
					};
				}
				return list;
			},
		},
	};
};

function formatCount(value) {
	const n = Number(value);
	if (!Number.isFinite(n)) return String(value ?? "");
	const units = [
		[1e12, "T"],
		[1e9, "B"],
		[1e6, "M"],
		[1e3, "K"],
	];
	for (const [size, suffix] of units) {
		if (Math.abs(n) >= size) return `${(n / size).toFixed(2)}${suffix}`;
	}
	return String(Math.round(n));
}

export default baigongPlugin;

/** 单测入口：不是函数，magpie 不会把它当插件调用。 */
export const _internal = { createPkce, codeFromLocalRedirect, formFields, casFailure, dropImages, parseExpiry, decodeEnvelope, formatCount };
