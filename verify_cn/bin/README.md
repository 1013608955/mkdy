# verify_cn/bin/ — hdspace CLI 放置处

`verify-cn-cloud.yml` 工作流通过 `verify_cn/cloud_control.sh` 远程控制华为云开发者空间容器，
脚本需要 **Linux AMD 64 位** 版的 `hdspace` 二进制，请按以下步骤放入本目录并提交：

## 获取 hdspace（Linux AMD 版）

1. 打开华为云开发者空间 → 云开发环境 → 找到你的容器实例（如 `DevEnvC_W4yNKt`）。
2. 点「远程连接」→ 在弹窗里**选 Linux / AMD 版本**（不是你本机用的 Windows `.exe`）→ 下载 tar 包。
3. 解压得到 `hdspace` 单文件可执行程序。

## 放置并提交

把解压出的 `hdspace` 放到本目录：

```
verify_cn/bin/hdspace
```

然后提交到仓库（`verify-cn-cloud.yml` 会在运行时执行它）。

> 说明：该二进制约几十 MB，直接进仓库即可（也可改为 GitHub Release 资产 + 工作流下载，
> 但提交进仓库最简单、最稳）。**切勿把 AK/SK、PAT 等密钥放进本目录或任何仓库文件。**

## 其他必需项（在仓库 Settings 配置，不进仓库）

- Secrets：`HW_AK`、`HW_SK`、`HW_INSTANCE_ID`、`HW_GITHUB_PAT`（细粒度 PAT，Contents:write）
- Secrets（可选）：`HW_SSH_USER`（默认 `developer`）、`HW_REGION`（默认 `cn-north-4`）
- Variables（可选）：`VERIFY_MAX_AGE_MIN`（新鲜度阈值/分钟，默认 `180`；调小=更频繁开机验证，
  调 `0`=每次触发都开机）
