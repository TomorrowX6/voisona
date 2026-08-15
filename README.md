# VoiSona 逆向分析与试用限制补丁

VoiSona (Techno-Speech, inc.) v1.18.0.5 的 DRM/API 逆向分析成果与试用限制（10 秒）补丁工具。

> ⚠️ **免责声明**：本项目仅供逆向工程学习与研究。修改商业软件可能违反其许可协议，请在法律允许的范围内使用。作者不对使用本工具造成的任何后果负责。

## 成果概览

1. **DRM 机制**：Mozart 账号授权（`https://voisona.com/api/v1`）+ libsodium secretstream 音源加密（密钥派生自内置常量 `TSVoiceEncKey001`）。
2. **声库下载端点**：`https://cdn.voisona.com/voice/{声库ID}/{版本}/{声库ID}.tsnvoice`（客户端本地拼接，CDN 直连）。
3. **试用限制补丁**：将试用音源 10 秒合成/导出限制改为 100000 秒（≈27.8 小时），共 10 处二进制补丁。

详见 [`docs/`](docs/) 下的分析文档。

## 补丁清单（v1.18.0.5，x64）

所有补丁把指向共享常量 `10.0`（`.rdata @0x1411A7DF0`）的 RIP 位移改指到内置的 `100000.0`（`0x1411A8030`），或直接修改条件逻辑：

| # | VA | 原字节 | 补丁字节 | 作用 |
|---|-----|--------|----------|------|
| p1 | `0x140AFBEB2` | `66 0F 2F 05 36 BF 6A 00` | `66 0F 2F 05 76 C1 6A 00` | UI 播放头 10s 检查 → 100000s |
| p2 | `0x140AF84C5` | `83 FA 0F` | `83 FA FF` | 禁用试用限制事件（case 0xF） |
| p3 | `0x140A7FD77` | `F2 0F 59 35 71 80 72 00` | `F2 0F 59 35 B1 82 72 00` | 引擎渲染位置检查 ×10 → ×100000 |
| p4 | `0x140A7FFC4` | `F2 0F 10 05 24 7E 72 00` | `F2 0F 10 05 64 80 72 00` | 引擎时间检查 10.0 → 100000.0 |
| p5 | `0x140A8017B` | `F2 0F 10 0D 6D 7C 72 00` | `F2 0F 10 0D AD 7E 72 00` | 引擎时长钳制 10.0 → 100000.0 |
| p6 | `0x140A6B9AF` | `F2 0F 59 05 39 C4 73 00` | `F2 0F 59 05 79 C6 73 00` | 时长计算 ×10 → ×100000 |
| p7 | `.rdata @0x140FE06F0` | `00 00 00 00 00 00 24 40` | `00 00 00 00 00 6A F8 40` | 钳制常量 10.0 → 100000.0 |
| p8 | `0x140B3B63A` | `80 F1 01` | `B1 01 90` | **导出曲目包含**：`!isTrial` → 恒包含 |
| p9 | `0x140B07326` | `0F 85 05 03 00 00` | `90 ×6` | 移除「试用&&导出→跳过渲染」 |
| p10 | `0x140B0F260` | `F2 0F 59 05 88 8B 69 00` | `F2 0F 59 05 C8 8D 69 00` | 导出时长计算 ×10 → ×100000 |
| p11 | `0x140A01A60` | `48 89 5C 24 08 ...` | `B0 01 C3` + `90×91` | **跳过登录**：`isAuthenticated()` 恒返回 true |
| p12 | `0x140B3530C` | `0F 84 FB 03 00 00` | `E9 FC 03 00 00 90` | **禁用更新检查**：恒走「已是最新版」路径（不发请求、不弹更新提示） |
| p13 | `0x140B35F3D` | `80 BB D0 36 00 00 00 0F 84 96 00 00 00` | `90 ×13` | **全新安装不弹登录界面**：移除 `RefreshUI()` 中「mail 为空 → 构建登录界面」的条件，恒走编辑器路径 |
| p14 | `0x140B32843` / `0x140B3EB38` | `80 BB D0 36 00 00 00 74 09` 等 | `90 ×9` ×2 | 移除声库刷新派发前的 mail 检查（防御性，配合 p11/p13） |
| p15 | `0x140B36578`（实验性） | `48 8B 45 7F 80 38 00 ...` | `lea`/`mov` 注入 .data 凭据 | **实验性未完成**：内嵌默认凭据自动登录。应用字符串为特殊布局，实测序列化不正确，默认不启用 |
| p16 | `0x14013D5C0` | `48 89 5C 24 08 57 48 83 EC` | `30 C0 C3` + `90×6` | **IsTrial() 恒返回 false**：核心试用判定（p1–p10 的检查点全部经由它），全部声库按已购买处理 |
| p17 | `0x1409F4425` | `C6 44 24 20 01` | `C6 44 24 20 00` | **徽标伪造**：trial_licenses 条目解析时试用标志 1→0，记录写入"已购"哈希 `0xC48682A2`（试用为 `0xB18097E6`），UI 显示已购买 |

## 使用方法

```powershell
# 1. 备份
Copy-Item "C:\Program Files\Techno-Speech\VoiSona\VoiSona.exe" "VoiSona.exe.bak"

# 2. 打补丁（对 exe 副本，脚本内含字节校验）
Copy-Item "C:\Program Files\Techno-Speech\VoiSona\VoiSona.exe" .\VoiSona.exe
powershell -ExecutionPolicy Bypass -File patches\apply_all_patch.ps1
powershell -ExecutionPolicy Bypass -File patches\apply_export_patch.ps1
powershell -ExecutionPolicy Bypass -File patches\apply_auth_patch.ps1
powershell -ExecutionPolicy Bypass -File patches\apply_update_patch.ps1
powershell -ExecutionPolicy Bypass -File patches\verify_final.ps1

# 3. 部署回 Program Files（需管理员）
powershell -ExecutionPolicy Bypass -File patches\deploy_patch.ps1
```

**还原**：用 `VoiSona.exe.bak` 覆盖回 `C:\Program Files\Techno-Speech\VoiSona\VoiSona.exe`。

## 目录结构

```
├── README.md
├── patches/
│   ├── apply_all_patch.ps1      # p1-p7（播放限制）
│   ├── apply_export_patch.ps1   # p8-p10（导出限制）
│   ├── apply_auth_patch.ps1     # p11+p13+p14（跳过登录 / 新装不弹登录界面）
│   ├── apply_update_patch.ps1   # p12（禁用更新检查）
│   ├── seed_config.ps1          # 全新安装写入 config.json 种子（声库列表所需凭据）
│   ├── verify_final.ps1         # 校验全部补丁
│   └── deploy_patch.ps1         # 部署到 Program Files（需管理员）
├── tools/
│   ├── capture_script.txt       # x64dbg 捕获脚本（-cf 参数运行）
│   └── derive_key.py            # TSVoiceEncKey001 密钥派生
└── docs/
    ├── DRM分析.md               # DRM 机制分析
    └── 下载端点分析.md            # API 声库下载端点分析
```

## 关键发现速览

- **API 基址**：`https://voisona.com/api/v1`（OAuth Basic 凭证硬编码 `mozart:xfGKApM)g7uS`）
- **声库激活**：`POST /api/v1/auth/activate/voice/`（启动时自动调用，`TS-Auth` 头）
- **声库下载**：`GET https://cdn.voisona.com/voice/<id>/<version>/<id>.tsnvoice`
- **音源加密**：libsodium `crypto_secretstream_xchacha20poly1305`，密钥 = `BLAKE2b-256(fmix32_mix(SHA-256 IV), key="TSVoiceEncKey001")` = `B3F724B6F59962D5DF2D910245E6AA20EA5D427BABC8F3BE789F8ABA30E39C70`
- **设备绑定**：`GetComputerNameExW`/`GetVolumeInformationW` 指纹 + 每账号设备数上限（`activation_limit_exceeded`）
- **登录凭证**：`Host\config.json` 中 `mail` + `license_key`（64 hex）即登录凭证 —— `license_key` 实为密码，启动时自动 `POST /api/v1/auth/token/` 登录换取 JWT，再依次 `POST /api/v1/auth/token/verify/`、`POST /api/v1/auth/activate/`（设备注册）、`POST /api/v1/auth/activate/voice/`（声库试用激活，请求体 `{"email","voice","version","type"}`）
- **声库列表来源**：列表 = 本地 `voices\Singer\<id>` 目录 + 账号许可信息；启动时**没有**独立的声库列表请求，列表在登录/激活回调链完成后由本地扫描构建（按需读取各声库图标）。因此无凭据的裸装无法列出本地声库
- **全新安装说明**：p13 后无配置也能进编辑器；声库列表依赖账号凭据，请用 `patches\seed_config.ps1` 写入 `config.json` 种子（写入 mail/license_key 后应用自动登录并列出全部本地声库）
