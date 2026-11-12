# TLS 1.3 Post-Handshake Authentication 接入评审说明（tlslite-ng 0.9.0b2）

## 1. 结论先行：`read()` 返回的数据能不能当成“已认证请求”？

**不能由传输层自动认定。** 发出 PHA 认证请求之后，`read()` 的行为是“按记录类型解复用”，不是“按认证状态过滤”：

- 服务端在有未完成的 PHA 请求时，`readAsync()` 同时接受 `application_data` 与 `handshake` 两类记录（`tlslite/tlsrecordlayer.py:330-366`）。
- PHA 的 `Certificate / CertificateVerify / Finished` 属于握手记录，在读取循环内部被 `_handle_srv_pha()` 消费，**永远不会进入应用的读缓冲**；能从 `read()` 拿到的只有 `ApplicationData`（`tlsrecordlayer.py:399-408`）。
- 因此，客户端在认证完成**之前**已经发出、滞留在管道里的应用数据，之后仍会被正常 `read()` 出来。tlslite-ng 不会给这些字节打“未认证”标记，也不会丢弃它们。
- 认证状态只体现在一个地方：连接对象上的 `session.clientCertChain`。它在 `_handle_srv_pha()` 全部校验通过后的**最后一行**才被赋值（`tlsrecordlayer.py:929`）。

所以应用必须自己维护准入闸门：**在 `read()` 得到应用数据时，以“当前连接的认证状态 + 该请求自身是否已完成过 PHA”来判定是否放行**，而不能假设“我发过 CertificateRequest，所以后面 read 到的都是认证过的”。

## 2. 当前实现的关键事实（均有源码/实测支撑）

### 2.1 协商与能力声明
- 客户端只有在初始握手时同时传入证书链和私钥，才会在 ClientHello 中携带 `post_handshake_auth` 扩展，并把凭据存入连接级字段 `_client_keypair`（`tlslite/tlsconnection.py:789-795`）。**空证书链 `X509CertChain()` 配私钥也会声明 PHA 能力**（见场景 2）。
- 完全匿名的客户端（无任何凭据）不声明该扩展，服务端 `_pha_supported=False`；此时调用 `request_post_handshake_auth()` 会立即抛 `ValueError("PHA not supported by client")`，不会在网络上发任何东西（`tlsconnection.py:2683-2686`，已实测）。
- PHA 仅支持 TLS 1.3，且只能由服务端发起（`tlsconnection.py:2681-2684`）。

### 2.2 请求是“异步”的，没有完成通知接口
- `request_post_handshake_auth(settings)` 是一个生成器，它生成 32 字节随机 `certificate_request_context`、构造并**仅发送** CertificateRequest，然后把该 context 登记进 `_cert_requests` 字典后返回；它**不等待**客户端响应（`tlsconnection.py:2672-2716`，docstring 原文：“The PHA process is asynchronous… it will not wait for it.”）。
- 库没有提供“PHA 完成回调 / Future / 事件”。完成只能在后续驱动记录层时观察到。约定用法是 `conn.read(0, 0)`：即使没有应用数据，也会处理 PHA（以及 NST、KeyUpdate）并返回 `b''`（`tlsrecordlayer.py:372-377`；官方测试 `tests/tlstest.py:3203` 即如此使用）。
- 客户端侧同样没有显式“应答 API”：当 `_client_keypair` 已设置时，客户端自己的 `read()` 循环收到 CertificateRequest 会自动调用 `_handle_pha()` 回复证书三件套（`tlsrecordlayer.py:402-404, 698-805`）。这意味着**客户端线程必须持续 pump 读取循环**，否则会与服务端在阻塞 socket 上互等死锁（场景 1 的线程编排即演示这一点）。

### 2.3 request context 如何把证明归到正确请求
- 每个 PHA 请求生成唯一随机 context，并保存在服务端 `_cert_requests[context]`（`tlsconnection.py:2696-2713`）。
- 客户端回复的 Certificate 消息必须**原样回显**该 context（TLS 1.3 协议要求，`_handle_pha` 用它构造证书消息，`tlsrecordlayer.py:728-731`）。
- 服务端 `_handle_srv_pha()` 用回显的 context 从字典里 `pop` 出原始请求；context 为空、未知或已被消费过，都会发 fatal `illegal_parameter` 告警并关连接（`tlsrecordlayer.py:815-830`）。这保证了每条证明严格对应一条未决请求，且不可重放。
- **该 context 是库内部状态，未通过任何公共属性暴露给应用**（已核对：仅存在于 `_cert_requests` 与消息对象中）。应用侧的“请求 ↔ 身份”关联需要用自己的请求 ID 建立：发起敏感请求 → 发送 PHA → 在同一个处理回合内 pump 完成 → 立刻读取 `session.clientCertChain` 并绑定到该请求 ID。场景 4 的 `AppGateway` 就是这个模式的最小实现。

### 2.4 校验、失败语义与身份生效时点
- 服务端依次校验：context 匹配、签名算法在通告列表内且与证书公钥一致、`CertificateVerify` 签名验证、`Finished` verify_data（`tlsrecordlayer.py:839-927`）。
- 任一校验失败 → 发 fatal alert 并 `_shutdown(False)`，**整条连接关闭**（实测双端 `closed=True`）。签名失败对应 `decrypt_error`（51）；空证书且 `client_cert_required=True` 对应 `certificate_required`（116）。
- `session.clientCertChain` 的赋值在所有校验之后（`tlsrecordlayer.py:929`），是同一个 Session 对象上的原地更新（实测 PHA 前后 `session` 实例不变、master secret 不变）。因此**不存在“半认证”可观察状态**：要么还是旧身份，要么已经是新身份。
- 空证书的两种策略（见场景 2 实测）：
  - `client_cert_required=False`（默认）：TLS 层接受空答复，但解析出的 `cert_chain` 为 `None`（`messages.py:1129-1138`），`session.clientCertChain` 保持 `None`，连接存活，应用应继续按匿名处理并自行拒绝敏感操作。
  - `client_cert_required=True`：库直接以 fatal `certificate_required` 关连接，应用代码没有机会误放行。

### 2.5 并发与重入限制（评审需知）
- `_cert_requests` 是连接上的字典，理论上允许同时挂多个未决 PHA 请求；但**库不提供任何把后续到达的证书与应用层请求做调度的机制**，且阻塞式 `read()` 模型下多未决请求会让“哪个请求先被满足”不可控。**建议同一连接上同一时刻只保留一个未决 PHA，严格“请求—完成—再下一个”串行化**（场景 4 即串行两轮）。
- 已完成的 context 会被 `pop`，重放同一 context 会触发 fatal alert。

## 3. 时序说明（评审版）

以“匿名建链 → 访问敏感接口触发 PHA → 成功后放行”为例，单条 TCP 字节流、单条 TLS 连接：

```
客户端                                          服务端
  │                                               │
  │ ── TLS1.3 完整握手（仅服务端认证）──────────► │ handshakeServer()
  │ ClientHello 带 post_handshake_auth(因已配凭据) │ _pha_supported = True
  │ ◄─────────────────────────────────────────── │ session.clientCertChain = None（匿名）
  │                                               │
  │ ── ApplicationData "GET /sensitive" ────────► │ read() 取出应用数据
  │                                               │ 查应用准入闸门：未认证 → 拒绝并触发 PHA
  │ ◄──────── CertificateRequest(context=C1) ─── │ request_post_handshake_auth() 仅发送后返回
  │   （客户端 read 循环内 _handle_pha 自动应答）  │ _cert_requests={C1: ...}
  │ ── Certificate(context=C1, 链) ─────────────► │
  │ ── CertificateVerify(签名) ─────────────────► │ read(0,0) 驱动 _handle_srv_pha：
  │ ── Finished(verify_data) ───────────────────► │  context 匹配 pop(C1) → 验签 → 验 Finished
  │                                               │  全部通过后 session.clientCertChain = 链 ★
  │ ── ApplicationData "重试 GET /sensitive" ───► │ read() 取数据；此时准入闸门显示已认证 → 放行
```

★ **业务可以认定新身份已经生效的唯一可观察时刻：驱动 PHA 完成的那次读取调用正常返回之后**（阻塞模型即 `conn.read(0,0)` 或下一次 `conn.read()` 未抛异常返回时），此刻读取 `conn.session.clientCertChain` 非空即代表新身份生效。在此之前读到的任何应用数据都必须按旧身份（匿名）处理。

失败时序：任一步校验不过 → 服务端发 fatal alert → 双端连接终止，`session.clientCertChain` 不被更新（保持 None 或旧身份），应用应把该连接视为不可用并要求重新建链。

## 4. 库提供的传输保证 vs 应用仍需做的准入判断

### 库保证（TLS 层，可直接依赖）
- PHA 消息与应用数据在同一加密连接上正确解复用，握手消息不会混入 `read()` 的应用字节流。
- 证书链、CertificateVerify 签名、Finished 的密码学校验由库完成；证明与请求通过 `certificate_request_context` 严格一一对应、不可重放，未知/重复 context 被拒绝。
- 校验失败即发 fatal alert 并关连接；身份字段仅在全部成功后原子更新，无中间态。
- PHA 不重新协商密钥，复用原连接的流量密钥与 master secret（实测 secret 不变）。

### 应用必须自行承担（库不做）
- **请求级授权**：库认证的是“整条连接的对端实体”，不是“某一条 HTTP 请求”。对到达的每条消息，应用要自行检查当前认证状态与权限（匿名期数据不得因“稍后会认证”而被预授权）。
- **请求与 PHA 回合的关联**：库不暴露 context，应用需用自己的请求 ID，在 PHA 完成的同一回合把读到的身份绑定到该请求（见 `AppGateway`）。
- **证书链的信任与授权决策**：tlslite-ng 默认不做链校验，需要应用用 `Checker`/自定义逻辑验证证书颁发者、有效期、用途、主体标识（如 SPIFFE ID/CN/SAN），并映射到业务身份与角色。
- **匿名期数据的处理策略**：对认证前到达的数据显式拒绝/缓存/丢弃，避免 TOCTOU。
- **串行化与超时**：保证单连接单未决 PHA，并为“发出 CertificateRequest 后客户端迟迟不应答”设置应用层超时与重试/断连策略（库的异步 API 本身不提供超时通知）。
- **空答复策略**：敏感接口应设置 `client_cert_required=True`，或在应用层对 `clientCertChain is None` 一律拒绝。

## 5. 最小接入示例

可运行版本见同目录脚本（内存 socketpair，无需端口/网络）：

- `demo_pha_common.py` — 证书加载、TLS1.3 匿名建链、线程协调、身份观察工具
- `scenario1_interleave.py` — 应用数据与 PHA 消息交错；`read()` 解复用与应用准入
- `scenario2_empty_cert.py` — 客户端空证书：可选策略（保持匿名）与强制策略（fatal 关连接）
- `scenario3_bad_signature.py` — CertificateVerify 无效：fatal `decrypt_error`，旧身份保留、连接关闭
- `scenario4_success_and_context.py` — 成功认证、请求级身份绑定、同连接二次 PHA 身份更新
- `run_all.sh` — 一键运行全部场景

服务端接入骨架（真实 socket 上同样适用）：

```python
from tlslite import TLSConnection, HandshakeSettings

tls13 = HandshakeSettings()
tls13.minVersion = tls13.maxVersion = (3, 4)

# 1) 匿名建链（不要求客户端证书）
conn.handshakeServer(certChain=server_chain, privateKey=server_key,
                     settings=tls13)
# 敏感接口要求强制证书时打开：conn.client_cert_required = True

def current_identity(conn):
    chain = conn.session.clientCertChain
    if not chain or not chain.x509List:
        return None                       # 仍为匿名
    return authorize(chain)               # 应用自行做链校验+身份映射

def handle_sensitive_request(conn, request_id, verified_requests):
    if request_id in verified_requests:
        return process(request_id)       # 本请求已绑定过身份
    # 2) 发起 PHA（仅发送，不等待）
    for _ in conn.request_post_handshake_auth(tls13):
        pass
    # 3) 驱动记录层完成 PHA；没有应用数据也要 pump
    conn.read(0, 0)
    identity = current_identity(conn)    # ★ 此刻起新身份生效
    if identity is None:
        raise PermissionError("client remained anonymous")
    verified_requests[request_id] = identity
    return process(request_id)
```

客户端骨架（注意必须有线程/事件循环持续 `read()` 以自动应答）：

```python
# 传入凭据才会声明 post_handshake_auth；凭据保存在连接上供 PHA 自动应答
conn.handshakeClientCert(client_chain, client_key, settings=tls13)
# 之后在读取循环里，CertificateRequest 会被库自动回复，无需额外 API
conn.read(0, 0)
```

## 6. 库中不存在、需应用补齐的接口（明确标注）

- 无 PHA 完成通知/回调/Future：完成只能通过 `read(0,0)/read()` 正常返回来观察。
- 不暴露 `certificate_request_context` 给应用：请求级关联靠应用自身请求 ID。
- 无 PHA 超时与取消机制：需应用层定时器。
- 无应用数据“认证标记”：`read()` 不区分字节到达于 PHA 前还是后，准入判断完全在应用。
- 无默认证书链信任校验：链验证与主体授权由应用通过 checker 实现。
