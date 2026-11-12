# TLS 降级防护接入指南（FALLBACK_SCSV 与 TLS 1.3 降级随机值）

本文依据本仓库 tlslite-ng 的实际实现撰写，替代旧版接入文档中
“打开 FALLBACK_SCSV 或 TLS 1.3 降级随机值中的任意一个，就能防止所有降级”
的说法。该说法不成立：这是两套**互相独立、触发方不同、覆盖版本区间不同**
的机制，必须分别理解、配合使用，并且都不能替代最低版本配置。

文中所有结论均可追溯到具体代码路径，或
`unit_tests/test_downgrade_protection.py` 中使用 `socket.socketpair()`
内存传输与 `tests/` 目录测试证书的本地握手测试（无网络、无监听端口）。

## 1. 两套机制不是一回事

| 维度 | TLS_FALLBACK_SCSV（RFC 7507） | TLS 1.3 降级随机值 sentinel（RFC 8446 §4.1.3） |
| --- | --- | --- |
| 信号方向 | 客户端在 ClientHello 的 cipher_suites 中携带 SCSV | 服务端把固定 8 字节写入 ServerHello.random 末尾 |
| 谁来检测并拒绝 | **服务端** | **客户端** |
| 触发条件 | 协商版本低于服务端 `maxVersion`，且 ClientHello 含 SCSV | 客户端支持更高版本，却协商到低版本且随机值带 sentinel |
| 拒绝告警 | `inappropriate_fallback`（86） | `illegal_parameter`（47） |
| 覆盖区间 | 任意相邻版本回退（含 1.3→1.2、1.2→1.1 等） | 仅“对端本可协商 TLS 1.3/1.2”的场景 |
| 前提 | 客户端只应在**自己主动重试回退**时设置 | 服务端必须确实支持更高版本才会盖 sentinel |
| 代码位置 | 客户端发送 `tlslite/tlsconnection.py:734`；服务端检测 `tlslite/tlsconnection.py:3757` | 服务端盖章 `tlslite/tlsconnection.py:2514`；客户端检测 `tlslite/tlsconnection.py:542`；常量 `tlslite/constants.py:28`、`tlslite/constants.py:32` |

关键点：

- SCSV 是**客户端自我声明**“我这次是降级重试”。默认关闭
  （`tlslite/handshakesettings.py:451`，`sendFallbackSCSV = False`），
  本库不内置任何自动重试，需要应用在自己的回退重试逻辑里显式打开。
  正常的首次握手**不要**带 SCSV。
- sentinel 是**服务端主动留痕**。服务端在自身支持更高版本、却协商到低版本时，
  无条件在 `ServerHello.random` 末尾盖章，与客户端是否带 SCSV 无关
  （`tlslite/tlsconnection.py:2517`-`tlslite/tlsconnection.py:2520`）。
- 两者检测的攻击面不同，不能互相替代：
  - 没有 SCSV 时，服务端无法区分“客户端天生只支持旧版本”和
    “客户端支持新版本但被中间人改写了 ClientHello”。
  - 没有 sentinel 时，一个支持 TLS 1.3 的客户端无法识破
    “支持 1.3 的服务端被中间人逼回 1.2/1.1”的攻击。

## 2. 服务端与客户端的实际代码行为

### 2.1 服务端：FALLBACK_SCSV 检测

`tlslite/tlsconnection.py:3757`：

```python
#Detect if the client performed an inappropriate fallback.
if version < settings.maxVersion and \
        CipherSuite.TLS_FALLBACK_SCSV in clientHello.cipher_suites:
    for result in self._sendError(
            AlertDescription.inappropriate_fallback):
        yield result
```

- 只有“协商版本 `<` 服务端 `maxVersion`”**且** ClientHello 带 SCSV 才拒绝。
- 协商版本等于服务端最高支持版本时，即使带 SCSV 也放行（这是合法的首次握手，
  见测试 `test_scsv_on_1_3_capable_peers_is_allowed`）。
- SCSV 不是真正的密码套件，是复用 cipher_suites 字段的信号值，
  码点 `0x5600`（`tlslite/constants.py:862`）。

### 2.2 服务端：sentinel 盖章

`tlslite/tlsconnection.py:2514`：

```python
random = getRandomBytes(32)
if version == (3, 3) and settings.maxVersion > (3, 3):
    random[-8:] = TLS_1_2_DOWNGRADE_SENTINEL      # ...444F574E47524401
if version < (3, 3) and settings.maxVersion >= (3, 3):
    random[-8:] = TLS_1_1_DOWNGRADE_SENTINEL      # ...444F574E47524400
```

- 协商 TLS 1.2 且服务端支持 1.3 → 盖 `...01`（“DOWNRG”+01）。
- 协商 TLS 1.1 及更早且服务端至少支持 1.2 → 盖 `...00`。
- 服务端本身只支持到 1.2 时，协商 1.2 不盖任何 sentinel——它没有更高版本可声明。
  因此**不能把“旧版本协商成功”一律当作攻击**。

### 2.3 客户端：sentinel 检测

`tlslite/tlsconnection.py:542`：

```python
# For TLS1.3
if (settings.maxVersion > (3, 3) and self.version <= (3, 3)) and \
        (serverHello.random[-8:] == TLS_1_2_DOWNGRADE_SENTINEL or
         serverHello.random[-8:] == TLS_1_1_DOWNGRADE_SENTINEL):
    # 发送 illegal_parameter 并终止："Connection terminated because
    # of downgrade protection."

# For TLS1.2
if settings.maxVersion == (3, 3) and self.version < (3, 3) and \
        serverHello.random[-8:] == TLS_1_1_DOWNGRADE_SENTINEL:
    # 同样发送 illegal_parameter 并终止
```

- 检测前提是**客户端自己的 `maxVersion` 高于协商结果**。一个 `maxVersion=(3,3)`
  的客户端不会评估 `...01` sentinel，因为它本来就不支持 1.3。
- 这正是“天生只支持旧版本的客户端不会误报”的代码依据：
  旧客户端的 `maxVersion` 不满足检测条件，连接正常完成。

### 2.4 最低版本 minVersion 的强制点

- 服务端在 `tlslite/tlsconnection.py:3459`：真实协商版本
  `< settings.minVersion` 时发 `protocol_version`（70）告警
  （`"Too old version"`）。
- 客户端在 `tlslite/tlsconnection.py:1118`：ServerHello 版本
  `< settings.minVersion` 时发 `protocol_version` 告警。
- 版本元组取值：SSL 3.0=`(3,0)`、TLS 1.0=`(3,1)`、TLS 1.1=`(3,2)`、
  TLS 1.2=`(3,3)`、TLS 1.3=`(3,4)`（`tlslite/handshakesettings.py:77`）。

## 3. 行为矩阵

记法：C = 客户端，S = 服务端；版本为各自 `minVersion`–`maxVersion` 区间。
“结果”列给出**拒绝方 + 告警**或协商成功的版本。全部行均由
`unit_tests/test_downgrade_protection.py` 中的测试复现。

### 3.1 正常协商与合法旧版本（不得报攻击）

| # | 客户端范围 | 服务端范围 | SCSV | 结果 | 测试 |
| --- | --- | --- | --- | --- | --- |
| N1 | 1.0–1.3 | 1.0–1.3 | 否 | 成功，TLS 1.3 | `test_tls13_normal` |
| N2 | 1.0–1.2 | 1.0–1.3 | 否 | 成功，TLS 1.2；服务端盖 `...01`，客户端不评估 | `test_genuine_legacy_client_tls12_is_not_an_attack` |
| N3 | 1.0–1.1 | 1.0–1.2 | 否 | 成功，TLS 1.1；服务端盖 `...00`，客户端不评估 | `test_genuine_legacy_client_tls11_is_not_an_attack` |
| N4 | 1.0–1.2 | 1.0–1.2 | 否 | 成功，TLS 1.2；无 sentinel（服务端不支持 1.3） | `test_legacy_only_server_with_matching_client` |
| N5 | 1.0–1.3 | 1.0–1.3 | 是 | 成功，TLS 1.3（协商版本=服务端最高版本，SCSV 不触发） | `test_scsv_on_1_3_capable_peers_is_allowed` |

N2/N3 是“客户端本来只支持旧版本”的对照：连接成功是预期行为，
监控系统不应将其标记为降级攻击。服务端盖 sentinel 只是留痕，
供**支持更高版本的**客户端使用，对旧客户端无意义。

### 3.2 主动回退（应用自身重试时带 SCSV）

| # | 客户端范围 | 服务端范围 | SCSV | 结果 | 测试 |
| --- | --- | --- | --- | --- | --- |
| F1 | 1.0–1.2 | 1.0–1.3 | 是 | **服务端拒绝** `inappropriate_fallback`，客户端收到同名远端告警 | `test_scsv_marks_inappropriate_fallback_to_tls12` |
| F2 | 1.0–1.1 | 1.0–1.2 | 是 | **服务端拒绝** `inappropriate_fallback` | `test_scsv_marks_inappropriate_fallback_to_tls11` |
| F3 | 1.0–1.1 | 1.0–1.2 | 否 | 成功，TLS 1.1（无法区分天生旧客户端，故放行） | `test_without_scsv_legacy_client_is_served` |

F1/F2 模拟的是应用实现 RFC 7507 回退重试：先用 1.3 握手失败，再降低
`maxVersion` 重连并置 `sendFallbackSCSV=True`。服务端发现自己本可提供更高版本，
判定为不当回退（典型成因是中间盒干扰了首次握手），拒绝连接。

### 3.3 中间人降级攻击（sentinel 路径）

测试用内存 MITM 代理改写 ClientHello：剥离 `supported_versions`(43)、
`key_share`(51)、`psk_key_exchange_modes`(45) 等 TLS 1.3 专属扩展，
改写 legacy `client_version` 并清空中间盒兼容 session_id，
使两端都支持 1.3 的连接被逼回旧版本。

| # | 真实客户端 | 真实服务端 | MITM 改写后 | 结果 | 测试 |
| --- | --- | --- | --- | --- | --- |
| A1 | 1.0–1.3 | 1.0–1.3 | 声称仅 1.2 | 服务端盖 `...01`；**客户端拒绝** `illegal_parameter` | `test_1_3_client_rejects_forced_tls12` |
| A2 | 1.0–1.3 | 1.0–1.3 | 声称仅 1.1 | 服务端盖 `...00`；**客户端拒绝** `illegal_parameter` | `test_1_3_client_rejects_forced_tls11` |

注意 A1/A2 中客户端发出的是本地告警（`TLSLocalAlert`），服务端随后收到的是
该告警回传形成的远端告警，因此测试里两端都观察到 `illegal_parameter`。
这条路径**不依赖 SCSV**：即便应用没有实现回退重试，sentinel 仍能识破攻击。

### 3.4 最低版本强制

| # | 客户端 | 服务端 `minVersion` | 结果 | 测试 |
| --- | --- | --- | --- | --- |
| M1 | 手工构造的裸 TLS 1.1 ClientHello | 1.2 | **服务端拒绝** `protocol_version`（"Too old version"） | `test_server_rejects_client_below_min_version` |
| M2 | 完整 tlslite 客户端，范围 1.0–1.1 | 1.1 | 成功，TLS 1.1 | `test_server_accepts_client_at_min_version` |

## 4. 本地握手样例（仅测试证书 + 内存传输）

以下代码与测试文件等价，可直接运行验证。证书取自仓库 `tests/serverX509Cert.pem`
与 `tests/serverX509Key.pem`，传输为 `socket.socketpair()`，不绑定任何端口。

```python
import socket, threading
from tlslite.api import X509, X509CertChain, parsePEMKey, TLSConnection, \
    HandshakeSettings
from tlslite.errors import TLSRemoteAlert, TLSLocalAlert
from tlslite.constants import AlertDescription

cert = X509CertChain([X509().parse(open("tests/serverX509Cert.pem").read())])
key = parsePEMKey(open("tests/serverX509Key.pem").read(), private=True)

def handshake(client_settings, server_settings):
    c_sock, s_sock = socket.socketpair()
    c_sock.settimeout(5); s_sock.settimeout(5)
    server_error = {}
    def server():
        try:
            TLSConnection(s_sock).handshakeServer(
                certChain=cert, privateKey=key, settings=server_settings)
        except TLSLocalAlert as alert:
            server_error["description"] = alert.description
    t = threading.Thread(target=server); t.start()
    conn = TLSConnection(c_sock)
    try:
        conn.handshakeClientCert(settings=client_settings)
        result = "negotiated %s" % (conn.version,)
    except TLSRemoteAlert as alert:
        result = "rejected by server: %s" % \
                 AlertDescription.toRepr(alert.description)
    t.join()
    if server_error:
        result += " (server sent: %s)" % \
                  AlertDescription.toRepr(server_error["description"])
    return result

# 正常 TLS 1.3
print(handshake(HandshakeSettings(), HandshakeSettings()))

# 主动回退到 1.2 且带 SCSV -> 服务端 inappropriate_fallback
fallback = HandshakeSettings()
fallback.maxVersion = (3, 3)
fallback.sendFallbackSCSV = True
print(handshake(fallback, HandshakeSettings()))

# 天生只支持 1.2 的客户端 -> 成功，不得报攻击
legacy = HandshakeSettings(); legacy.maxVersion = (3, 3)
print(handshake(legacy, HandshakeSettings()))
```

实测输出（对应测试 F1、N2）：

```text
negotiated (3, 4)
rejected by server: inappropriate_fallback (server sent: inappropriate_fallback)
negotiated (3, 3)
```

完整的 MITM 攻击复现（A1/A2）见测试中的 `downgrade_mitm()` 工厂函数。

## 5. 接入建议

1. **服务端始终保持默认 sentinel 行为**，不要尝试关闭；它是自动生效的，
   代码路径 `tlslite/tlsconnection.py:2514` 无开关。
2. **客户端仅在自己实现“先高后低”重试时**，对重试握手设置
   `settings.sendFallbackSCSV = True`；首次握手保持默认 `False`。
   本库不会自动重试，也不会自动设置该标志
   （`tlslite/handshakesettings.py:451`）。
3. **显式设置 `minVersion`** 作为安全基线（例如服务端 `(3,3)`）。
   两套降级机制检测的是“能力与协商结果不一致”，而 `minVersion`
   决定的是“无论如何都不接受的下限”，三者解决不同问题：
   - SCSV/sentinel：发现并阻断**降级攻击或不当回退**；
   - `minVersion`：从协议层面**禁止弱版本**，即使对端真诚地只支持旧版本，
     或攻击者把所有降级信号都抹掉，也无法建立低于基线的连接
     （`tlslite/tlsconnection.py:3459`、`tlslite/tlsconnection.py:1118`）。
4. **告警监控按告警类型区分语义**：
   - `inappropriate_fallback`(86)：服务端侧，客户端回退重试被拒；
   - `illegal_parameter`(47) 且消息为 "downgrade protection"：客户端侧，
     识破中间人降级；
   - `protocol_version`(70)：版本低于对端配置的 `minVersion`。
   不要把 N2/N3 这类无告警的旧版本成功握手计入攻击事件。

## 6. 实现层面的已知边界（接入方须知）

以下行为由代码与测试确认，配置时应纳入评估：

- 客户端 `HandshakeSettings.validate()` 不会按 `minVersion/maxVersion`
  过滤 `settings.versions`（`tlslite/handshakesettings.py:638`
  的 `_sanityCheckProtocolVersions` 仅在 `maxVersion < (3,4)` 时移除 1.3）。
  因此把客户端 `maxVersion` 降到 1.2/1.1 时，legacy `client_version`
  会随之降低，但若 `maxVersion` 仍为 1.3，`supported_versions` 扩展仍可能
  包含低于 `minVersion` 的条目。服务端的 `minVersion` 判定以
  ClientHello 宣告的最高版本（含 `supported_versions`）为准
  （`tlslite/tlsconnection.py:3452`），这也是 3.4 节使用裸 ClientHello
  验证强制效果的原因。
- 服务端的 FALLBACK_SCSV 检测对 TLS 1.3 协商同样生效，但仅当协商结果
  低于服务端 `maxVersion` 时触发（`tlslite/tlsconnection.py:3758`）。
  上游 `tests/tlstest.py:1615` 等处留有 "TODO fix FALLBACK_SCSV with
  TLS 1.3" 注释，接入方应依赖本文件测试矩阵而非旧注释描述的行为。
- sentinel 只覆盖服务端降级方向；它无法替代证书校验、密码套件约束等
  其他安全控制。

## 7. 复现方式

```sh
.venv/bin/python -m pytest -q -o addopts= \
    unit_tests/test_downgrade_protection.py
```

预期：13 passed。基线回归：

```sh
.venv/bin/python -m pytest -q -o addopts= \
    unit_tests/test_tlslite_messages.py \
    unit_tests/test_tlslite_extensions.py
```

预期：586 passed, 1 skipped（2026-11-11 本地实测）。
