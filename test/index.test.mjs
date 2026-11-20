import { test, expect } from "bun:test";
import plugin, { _internal } from "../index.mjs";

const { dropImages, parseExpiry, formFields, casFailure, formatCount, num, createPkce } = _internal;

test("dropImages 一张都不丢", () => {
	const body = { messages: [{ role: "user", content: [{ type: "text", text: "hi" }] }] };
	expect(dropImages(body)).toBe(0);
	expect(body.messages[0].content).toHaveLength(1);
});

test("dropImages 只留最新那一张", () => {
	const a = { type: "image_url", image_url: { url: "data:1" } };
	const b = { type: "image_url", image_url: { url: "data:2" } };
	const body = {
		messages: [
			{ role: "user", content: [{ type: "text", text: "a" }, a] },
			{ role: "user", content: [{ type: "text", text: "b" }, b] },
		],
	};
	expect(dropImages(body)).toBe(1);
	const types = body.messages.flatMap((m) => m.content.map((p) => p.type));
	expect(types.filter((t) => t === "image_url")).toHaveLength(1);
	// 丢掉的图换成一行文字，不是把消息清空
	expect(body.messages[0].content.at(-1).text).toContain("已省略 1 张");
});

test("dropImages 内容不是数组时不炸", () => {
	const body = { messages: [{ role: "user", content: "纯文本" }, { role: "user" }] };
	expect(dropImages(body)).toBe(0);
	expect(dropImages({})).toBe(0);
});

test("dropImages 一张都不留时补文字", () => {
	const body = { messages: [{ role: "user", content: [{ type: "image_url", image_url: { url: "data:1" } }] }] };
	expect(dropImages(body, 0)).toBe(1);
	expect(body.messages[0].content).toHaveLength(1);
	expect(body.messages[0].content[0].type).toBe("text");
});

test("parseExpiry 秒 / 毫秒 / ISO / 缺省", () => {
	const now = Date.now();
	expect(parseExpiry(1_700_000_000, 0)).toBe(1_700_000_000_000);
	expect(parseExpiry(1_700_000_000_000, 0)).toBe(1_700_000_000_000);
	expect(parseExpiry("2026-12-20T05:27:25Z", 0)).toBe(Date.parse("2026-12-20T05:27:25Z"));
	const fallback = parseExpiry(undefined, 60_000);
	expect(fallback).toBeGreaterThanOrEqual(now + 59_000);
});

test("num 不把 null / 空串当成 0", () => {
	expect(Number.isNaN(num(null))).toBe(true);
	expect(Number.isNaN(num(""))).toBe(true);
	expect(Number.isNaN(num(undefined))).toBe(true);
	expect(num(0)).toBe(0);
	expect(num(12.5)).toBe(12.5);
});

test("formFields 只拿 hidden 与 CAS 需要的字段", () => {
	const html = `
		<input type="hidden" name="execution" value="e1s1" />
		<input type="hidden" name="lt" value="LT-1" />
		<input type="text" name="username" value="" />
		<input type="text" name="_eventId" value="submit" />`;
	expect(formFields(html)).toEqual({ execution: "e1s1", lt: "LT-1", _eventId: "submit" });
});

test("casFailure 认出错误提示与验证码", () => {
	expect(casFailure('<span id="msg">用户名或密码错误</span>')).toEqual({ message: "用户名或密码错误", captcha: false });
	expect(casFailure('<input type="text" name="captcha" />').captcha).toBe(true);
	expect(casFailure("<html></html>")).toEqual({ message: "", captcha: false });
});

test("createPkce 是 S256 + base64url", () => {
	const { verifier, challenge, state } = createPkce();
	expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
	expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
	expect(state).toMatch(/^[A-Za-z0-9_-]{22}$/);
	expect(challenge).not.toBe(verifier);
});

test("formatCount 换算成人看的量级", () => {
	expect(formatCount(989_241_788_857)).toBe("989.24B");
	expect(formatCount(1_000_000)).toBe("1.00M");
	expect(formatCount(999)).toBe("999");
});

test("插件本体形状对：只有 default 是函数，钩子齐全", async () => {
	expect(typeof plugin).toBe("function");
	const hooks = await plugin({});
	expect(Object.keys(hooks).sort()).toEqual(["auth", "config", "provider"]);
	expect(hooks.auth.provider).toBe("baigong");
	expect(hooks.auth.methods).toHaveLength(1);
	expect(hooks.auth.methods[0].prompts.map((p) => p.key)).toEqual(["username", "password"]);

	const cfg = {};
	await hooks.config(cfg);
	const provider = cfg.provider.baigong;
	expect(Object.keys(provider.models)).toEqual(["ybg-youlaber-ds4f", "ybg-youlaber-ds4pro"]);
	for (const model of Object.values(provider.models)) {
		expect(model.modalities.input).toContain("image");
		expect(model.limit).toEqual({ context: 262_144, output: 32_768 });
		expect(Object.keys(model.variants)).toEqual(["low", "high", "xhigh", "max"]);
	}
});
