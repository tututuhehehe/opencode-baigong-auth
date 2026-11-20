# opencode-baigong-auth

邮百工（北邮）模型网关的 magpie / OpenCode 供应商插件：**学号密码直登，不打开浏览器**，顺带显示套餐和余额。

> **使用范围：仅限北京邮电大学（BUPT）在校师生。**
> 这个插件只是把学校的网关接到 magpie 上，本身不提供任何模型或额度。
> 登录用的是北邮统一身份认证（`auth.bupt.edu.cn`）的学号 + 密码，
> 账号和额度都由学校 / 邮百工平台发放，**非北邮学生无法使用**。
> 少数院系用的「校园账号」是邮百工团队或任课教师单独开的号，走 `POST /login`，
> 与统一认证不通用（插件会自动先试统一认证，失败再试这条路）。

```
magpie plugin add ./opencode-baigong-auth   # 或者 magpie plugin add opencode-baigong-auth（已发布时）
magpie plugin login baigong                 # 问学号、密码（掩码），HTTP 直连统一认证
magpie provider test baigong                # ✓ chat · ms
magpie quota                                # 免费体验版 · 余额 · 套餐额度
```

应用里同一件事：**供应商 → 添加供应商 → 插件中还有更多 → 邮百工（北邮）→ 填学号密码 → 添加**。
登录后这一行会显示身份、套餐、余额卡；`magpie quota` / 额度页看到的是同一份数据。

## 登录怎么走的（无浏览器）

只有北邮的账号走得通：统一认证地址写死为 `https://auth.bupt.edu.cn`，service 指向邮百工的
`/edugate/api/cas-callback`。

```
① POST {edugate}/local-auth/start                 PKCE(S256) → request_id
② GET  {cas}/authserver/login?service=…           → execution（CAS 表单，密码不加密）
③ POST 同一地址 {username, password, execution}   → 302 …/cas-callback?ticket=ST-…
④ 跟随 302                                        → {web}?cas_login=success&token=…
⑤ POST {edugate}/local-auth/complete              → local_redirect_url(code)
⑥ POST {edugate}/local-auth/exchange              → access_token / refresh_token
⑦ GET  {edugate}/local-auth/runtime-config         HKDF+AES-256-GCM 信封 → apiBase / apiKey / models[]
```

平台自建账号走另一条：`POST {edugate}/login {username, password, local_request_id}`，其余相同。
两条自动选：北邮统一认证先试，失败再试平台账号，两条都失败才报错（两条原因一起给）。

学号密码会作为账号字段存在 magpie 的 `plugin-auth.json`（600）里，唯一用途是 refresh 过期后静默重登一次；
错密码只重试一次，不会反复打到 CAS。

## 模型

模型名就是上游的 id（`ybg-youlaber-ds4f` / `ybg-youlaber-ds4pro`），agent 里看到的就是这两个。

文本 + 图像 + 思考 + 工具调用。思考档位只有 `low / high / xhigh / max`（上游只收这四档，minimal / medium 会 400）。

**图片：一次请求只收 1 张。** 上游 vLLM 的 `--limit-mm-per-prompt image=1`，多一张就直接
`400 At most 1 image(s) may be provided in one prompt.`。两层保险：

1. magpie 的供应商字段 `max-images=1`（编辑页「高级 › 每次请求的图片数」或
   `magpie provider set baigong max-images=1`）——保留最新的、更早的换成一行文字；
2. 插件 `fetch` 里同样的规则再兜一层（`IMAGES_PER_REQUEST = 1`），免得那个字段没设上时被上游拒掉。

更早的图片会被换成「[已省略 N 张较早的图片：该模型每次请求只收 1 张]」，会话照常继续。

| 模型 | 上下文 | 输出 | 谷价（USD / 百万 token） |
|---|---|---|---|
| `ybg-youlaber-ds4f` | 262144 | 32768 | in 0.15 · out 0.6 · cache read 0.003 |
| `ybg-youlaber-ds4pro` | 262144 | 32768 | in 0.66 · out 1.98 · cache read 0.022 |

云端 `runtime-config` 里下发的新模型会自动并进来，不用改代码。

## 计价：写的是谷价

DeepSeek 上游是峰谷计价（高峰 = 谷价 ×2）。插件里 `cost` 写的是**谷价**，所以显示永远是便宜那一档；
高峰时段真实花费是显示值的两倍。

要让 magpie 按峰谷算，在供应商编辑页「Rate windows」里加两条（本机时区 = 北京时间）：

| 起 | 止 | 倍率 | 星期 |
|---|---|---|---|
| 08:30 | 23:59 | 2 | 全选 |
| 00:00 | 00:30 | 2 | 全选 |

谷时 00:30–08:30 不加窗口，就按谷价算。magpie 只在它自己认识这个字段时才计峰谷；
插件在 `config` 里写的 `rateWindows` 会被忽略（实测），所以只能手动加一次。

## 其它设置

```
magpie provider set baigong context=256k max-images=1   # 编辑页「高级」里那两个
```

上下文和最大输出已经写在模型 `limit` 里（262144 / 32768），上面这条只是让编辑页「高级」里也显示出来；
`max-images=1` 就是上面说的「一次请求只收 1 张」，设上更稳（插件里的兜底规则一样）。

`provider set` **没有** output 键（`output=` / `max-output=` / `outputs=` 都会被拒），
最大输出只能改代码里的 `MAX_OUTPUT_TOKENS`。压缩阈值也不在这里：
`magpie model compact <agent> <size>` 是按 agent 算的。

## 测试

```bash
bun test        # 纯函数：丢图、CAS 表单解析、PKCE、解析到期时间、插件形状
```

## 平台

插件本身用 Bun 跑（magpie 自带），只用 `node:crypto` / `node:net` 和 `fetch`，没有运行时依赖，
没有 postinstall，Windows / macOS / Linux 一样。
