# TLS 1.3 Post-Handshake Authentication 演示（tlslite-ng）

纯内存演示：通过 `socket.socketpair()` 在两个线程间建立 TLS 1.3 连接，
不监听任何端口、不访问网络。证书复用仓库 `tests/` 下的测试 PEM。

## 运行

在仓库根目录执行（需要让本树的 `tlslite` 包可被 import）：

```sh
./demo/pha/run_all.sh
# 或单独运行
python3 demo/pha/scenario1_interleave.py
```

## 文件

| 文件 | 覆盖内容 |
| --- | --- |
| `demo_pha_common.py` | 证书加载、TLS1.3 匿名建链、线程门控、身份观察工具 |
| `scenario1_interleave.py` | 应用数据与 PHA 握手记录交错；`read()` 只解复用、不做授权 |
| `scenario2_empty_cert.py` | 客户端空证书：可选策略保持匿名；强制策略触发 fatal `certificate_required` |
| `scenario3_bad_signature.py` | CertificateVerify 验签失败：fatal `decrypt_error`、连接关闭、旧身份保留 |
| `scenario4_success_and_context.py` | 成功认证、请求级身份绑定、同连接二次 PHA 身份更新 |
| `PHA_REVIEW.zh-CN.md` | 面向后端接口评审的时序说明、传输保证与应用准入职责 |

## 观察要点

- 身份唯一可观察来源：`conn.session.clientCertChain`，仅在 PHA 全部校验
  通过后由库原地更新。
- 驱动 PHA 完成：服务端在发出 `request_post_handshake_auth()` 后，用
  `conn.read(0, 0)` pump 记录层；正常返回即代表该回合结束。
- 客户端必须有线程持续 `read()`，收到 CertificateRequest 时库会自动应答。
