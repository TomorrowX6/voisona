# VoiSona DRM 机制分析

> 目标：VoiSona.exe v1.18.0.5（Techno-Speech, inc.）— x64 原生 C++（JUCE + onnxruntime + 内部 TSSoftware 库），未加壳。
> 方法：静态反汇编（objdump 500MB .text）+ 字符串/RVA 交叉引用 + x64dbg 动态调试 + 本机安装状态核对。

## 总体架构

VoiSona 的 DRM 是**双层架构**：

```
第一层：Mozart 账号授权系统（在线激活 + 设备限额 + 音源许可）
第二层：音源数据加密（libsodium secretstream）
```

---

## 第一层：Mozart 账号授权

### 组件（RTTI 证据）

| 组件 | 说明 |
|---|---|
| `MozartApiClient`（含 `Listener`） | 授权 API 客户端 |
| `MozartAuthenticationContent` | 登录 UI |
| `LicenseInformation_V2`、`AuthInfo` | 授权信息模型 |
| `MozartDummy` | 无网环境回退假客户端 |
| 项目代号 `Mozart_Desktop` | 源码路径 `C:\actions-runner\_work\Mozart_Desktop\...` |

### 通讯协议（全部硬编码于 exe）

- **API 基址**：`https://voisona.com/api/v1`（全局 `0x1413B1B80`）
- **端点**：`auth/token/`、`auth/token/verify/`、`auth/token/refresh/`、`auth/activate/`（设备激活）、`voice/`、`voice/activate/`、`news/`、`editors/latest/`
- **认证头**：
  - `Authorization: Basic` + 硬编码 OAuth 客户端凭证 **`mozart:xfGKApM)g7uS`**（`0x140FC5B28`）
  - `Authorization: Bearer`（用户 access token）
  - `TS-Auth:`（Techno-Speech 签名头）
  - `TS-EngineType:`、`Content-Type:application/json`
- **登录请求体**：`{email, password, plugin_type, host, os_name, api_enabled, type}`
- **设备激活**：`{device, hardware, type, email, code, url}`；错误态含 **`activation_limit_exceeded`**（每账号设备数上限）
- **错误枚举**：`success` / `activation_limit_exceeded` / `disallow_user_error` / `unknown_error` / `network_error` / `parse_error` / `no_response_body_error` / `server_error_<code>` / `invalid_server_error`

### 本地状态持久化（实测）

`%APPDATA%\Techno-Speech\VoiSona\Host\config.json`：

```json
{ "mail": "...", "license_key": "<256位hex>", ... }
```

另有 `licenses[]` / `trial_licenses[]` 数组（元素：`name`、`is_active`、`is_adult`、`purchase_flow`、`purchase_text`、`purchase_link`）。

### 设备指纹

导入函数：`GetComputerNameExW` + `GetVolumeInformationW`（卷序列号）+ `GetSystemInfo` + 注册表读取。

---

## 第二层：音源加密

### 加密方案：libsodium `crypto_secretstream_xchacha20poly1305`（已确认）

| 证据 | 出处 |
|---|---|
| 解密状态 0x34=52 字节（`sodium_memzero`） | `SodiumDecryptor` 析构 `0x140412AC0` |
| 读 24 字节 header | `0x140412904` |
| 块开销 +0x11=17 字节（16 MAC + 1 tag） | `0x140412950` |
| **`TAG_FINAL`(=3) 检查** + "Stream truncated: TAG_FINAL not received" | `0x140412E61` |
| "Stream corrupted or tampered: MAC verification failed" | `0x140412EA7` |

**加密流格式**：`u32 version(=0) | 24B secretstream header | u32 chunk_size(≤16MB) | 加密块序列…`

### 密钥派生（完整逆向，`0x140412480`）

```
intermediate[i] = murmur3_fmix(i * 0x9E3779B9 XOR SHA256_IV[i])   (i=0..7, u32 LE)
key = BLAKE2b-256(intermediate, key="TSVoiceEncKey001")
    = crypto_generichash(out,32, in,32, key,16)
```

- 混淆表 `0x140F340D8` = SHA-256 初始化常量（0x6A09E667…）
- 密钥字符串 `TSVoiceEncKey001` @ `0x140F340F8`
- 派生后 `sodium_mprotect_readonly` 保护密钥

**最终密钥**：`B3F724B6F59962D5DF2D910245E6AA20EA5D427BABC8F3BE789F8ABA30E39C70`
（hashlib 与 pycryptodome 双实现交叉验证一致）

### 实际文件状态（实测熵分析）

- 试用 `.tsnvoice`：未加密（熵 ~6.5，FP16 权重明文）
- `dict.bin` 等词典：未加密（含明文字符串）
- 付费音源：secretstream 加密
- 配置开关 `SYNTHESIZER_ALLOW_NOT_ENCRYPTED_VOICE` 允许加载未加密音源

---

## 试用限制（10 秒）

- 试用音源合成/播放限制 10 秒（`TrialOnly="1"` 于 VoiceInformation XML）
- 导出（Audio Mixdown）时试用音源曲目被整体排除（`includeFlag = !isTrial`）
- 10 处二进制补丁见 [README](../README.md) 补丁清单

---

## 安全评估（客观）

| 层面 | 强度 |
|---|---|
| 音源加密（secretstream MAC） | 密码学本身强；但密钥完全静态派生（`TSVoiceEncKey001` 可从 exe 提取） |
| 账号授权 + 设备限额 | 有效遏制普通拷贝；`license_key`/`licenses` 存于本地明文 config.json |
| 试用限制 | 引擎/UI 多处 10.0 常量检查，可二进制补丁 |
| MAC 防篡改 | 有效：任何修改会 "MAC verification failed" |
