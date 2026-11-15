# 安卓投屏 · UGOS Pro 打包项目

把 [ws-scrcpy-web](https://github.com/RideWindOne/ws-scrcpy-web) 打成绿联 UGOS Pro 可安装的 `.upk`，
装完在桌面/App 的应用窗口里（inner iframe）直接打开、能登录、能投屏。

当前产物：`arm64_nasync_com.ridewind.wsscrcpyweb_0.5.11.0025.upk`（见 Release）。

## 为什么需要这个项目

镜像本身能跑，但在 UGOS 里"点开就白屏"。根因不在 CORS，而是服务端自己的三个行为，都发生在跨源 iframe 里：

1. `X-Frame-Options: SAMEORIGIN` —— 应用被放进 `app-xxx.ugapp.link` 的 iframe，浏览器直接拒绝渲染。
2. `set-cookie: ws_scrcpy_token=…; SameSite=Strict` —— 第三方上下文里这个 cookie 存不住也带不上，登录态必丢。
3. `Host` 被中转改写而 `Origin` 仍是 `app-xxx.ugapp.link`，服务端判定跨源，`POST /api/auth/login` 直接
   `{"error":"forbidden","reason":"cross-origin request rejected"}`。

另外 UGOS 打开应用前会探测 `/api/ugreen/auth`，非 200 就判"应用不可用"；`config.json` 缺
`baseAccessInfo.portInfo` 时网关注册失败（`PortInfo is nil`、点开报"无法访问"），缺 `allowedHosts` 时报
`host not allowed (possible DNS rebinding)`。

## 单容器结构

早期是 `ws-scrcpy-web` + `ws-gate` + `ws-open-fixer` 三个容器，现在合成一个：

```
主进程 root（覆盖镜像 entrypoint，自己 chown /data）
  ├─ 子进程 uid 1000：/bin/bash /app/start.sh，真实服务跑容器内 8001
  ├─ 自身监听 8000（对外唯一发布端口）
  │    应答 /api/ugreen/auth 探测 · 去掉 X-Frame-Options · 下发 CSP frame-ancestors
  │    cookie 改 SameSite=None+Secure · 代持 ws_scrcpy_token · Host 对齐 Origin
  └─ 启动 6 秒后跑安装补丁
       补 config.json 的 portInfo · 同步 .check-upk 的 hash · 补 allowedHosts
```

`app.js` 是这一整套逻辑的唯一实现（`gate.js` 是早期独立代理，保留作参考）。

合并后的两处必要改编：

- 原来靠 `docker restart` 让 `allowedHosts` 生效，合并后不能重启自己，改成杀服务子进程再拉起。
- 冷却守卫从 `/tmp/patched` 挪到 `/data/.fixer-last-restart`、`/data/.fixer-patched`，`/tmp` 的原路径会随容器重启失效。

`privileged` + `pid: host` 是 `nsenter -t 1 … systemctl restart app_serv.service` 需要的。

## 构建

依赖 [ugcli](https://github.com/RideWindOne) 与 Docker。

镜像不进仓库（单个 480M，超过 GitHub 100MB 限制），构建前自己准备：

```bash
docker pull ridewindone/ws-scrcpy-web:0.5.11
docker save ridewindone/ws-scrcpy-web:0.5.11 -o rootfs_arm64/images/ws-scrcpy-web.0.5.11.tar
```

校验与打包：

```bash
ugcli check --path .
ugcli pack --arch arm64 --build 25      # --build 要传整数，传 0025 不生效
```

产物在 `build_dir/pkgs/upk/arm64_nasync_com.ridewind.wsscrcpyweb_0.5.11.0025.upk`。

## 目录

| 路径 | 用途 |
|---|---|
| `project.yaml` | 应用元信息：`port: 8000`、`proxy_path: /`、`open_type: inner`，无安装参数 |
| `app.js` | 单容器入口：chown + 服务子进程 + 代理 + 安装补丁 |
| `rootfs_common/docker-compose.yaml` | 单服务 compose，entrypoint 覆盖成内联 `node -e` |
| `rootfs_common/icon.png` | 桌面图标 |
| `rootfs_arm64/images/` | 镜像 tar（构建时生成，不入库） |

## 踩过的坑

- `ports` 项之间夹注释 → `PortBindings=map[8000/tcp:[{invalid IP 8000}]]`，端口不发布，UGOS 判启用失败并 kill(137)
- compose 里出现字面 `$`（含注释、正则行尾锚）会被模板当变量；`{{` 会报 `missing value for if`
- `ports` 不能带模板表达式，`ugcli` 校验报 `Invalid containerPort`
- 通过环境变量传 `ACCOUNT/PASSWORD/AUTHKEY/DOMAINS` 无效，镜像里没有任何代码读取这四个变量
- 往 `/app/dist/api/ugreen/` 放静态文件无效，该路径仍然 403
- 用 curl 状态码判断域名可用性不可靠，200 可能是 `<script>window.location.href="https://www.ug.link/errorPage"</script>`
- `spawn('/bin/sh', ['/app/start.sh'])` 会报 `Bad substitution`，`start.sh` 是 bash 脚本

## 验证

```bash
# 不启补丁、只验证代理行为
docker run --rm -p 8003:8000 --network wsscrcpyweb_default \
  -e WS_SKIP_FIXER=1 --entrypoint node \
  ridewindone/ws-scrcpy-web:0.5.11 -e "$(cat app.js)"

curl -s "http://127.0.0.1:8003/api/ugreen/auth?token=t"     # {"code":0,"success":true}
curl -si "http://127.0.0.1:8003/" -H "Origin: https://app-x.ugapp.link" | grep -i "x-frame-options|content-security-policy|set-cookie"
```
