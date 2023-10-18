# 概述

跨语言移植一直是技术领域内难以解决的问题，需要解决语言之间的约束，好在先前我们成功使用 Go 实现了 IIOP 协议通信，有了前车之鉴，所以这次我们将继续使用跨语言方式实现 Flask Session 伪造。本文以 Apache Superset 权限绕过漏洞（CVE-2023-27524） 为例讲述我们是如何在 Go 中实现 Flask 框架的 Session 验证、生成功能的。

最终，我们在 Goby 中成功使用跨语言方式实现了 CVE-2023-27524 漏洞的检测与利用效果，并加入了一键获取数据库凭据，一键反弹 shell 的利用方式：

![在这里插入图片描述](https://img-blog.csdnimg.cn/35fb0f3442554a938a535fe88ff83da2.gif#pic_center)


# 漏洞原理

Session（会话）是一种服务器端管理的数据存储机制，用于在用户与 Web 应用程序之间保持持久性状态信息。它允许 Web 应用程序在不同 HTTP 请求之间存储和检索用户特定的数据。

当用户首次访问 Web 应用程序时，服务器会为每个用户创建一个唯一的会话标识（通常是一个会话 ID 或令牌），该标识存储在用户的浏览器中的 Cookie 中或通过 URL 参数传递。服务器使用此标识来跟踪特定用户的会话。

**如果我们能创建具有特权用户的 Session ，则可以执行后台危险操作，比如执行命令、上传文件等操作。**

在本例中，Apache Superset 所使用的 Flask 是一个微型的 Python Web 框架，在许多项目都有应用，比如 Flask-Chat、Flask-Blog、Flask-Admin 等，如果没有更改默认的 Flask 配置，则可能造成潜在的漏洞：



![在这里插入图片描述](https://img-blog.csdnimg.cn/91c00160605749799ee243010dcf4f08.png#pic_center)


攻击者首先发送请求登录的包，将回显包的 Flask Session 复制下来，并通过 session.decode 方法解码 Session 中的 Session Data。其次通过 session.verify 方法来校验 Flask Session 是否采用了默认密钥。如果为默认密钥则使用 session.sign 方法将密钥和解码后的 Session Data 生成对应的 Flask Session，从而达到权限绕过的目的。

因此要使用该权限绕过漏洞，需要了解 Flask Session的组成结构：

![在这里插入图片描述](https://img-blog.csdnimg.cn/98c45028f42244c09ae2da9486994110.png#pic_center)


Flask Session 的组成结构主要由三部分构成，第一部分为 Session Data ，即会话数据。第二部分为 Timestamp ，即时间戳。第三部分为 Cryptographic Hash ，即加密哈希。**只有符合 Flask Session的组成结构的 Session 才会被 Flask 正确解析。**

# Flask Session

由于 Go 语言中目前没有现成的 Flask 框架 Session 生成机制，所以需要用 Go 复刻 Flask Session 的核心代码以作为最终的通用解决方案。 

## session.decode 

```python
    try:
        decoded = session.decode(session_cookie)
        print(f'Decoded session cookie: {decoded}')
    except:
        print('Error: Not a Flask session cookie')
        return
```

在 Python 代码中， session.decode 方法的作用为检验传入的 Session 值是否为 Flask Session。因此，在 Go 语言中实现同等逻辑即可，具体需要下断点调试，从源码的角度查看 session.decode  的执行流程。

session.verify 方法源码如下：

```python
def decode(value: str) -> dict:
    try:
        compressed = False
        payload = value
        if payload.startswith('.'):
            compressed = True
            payload = payload[1:]
        data = payload.split(".")[0]
        data = base64_decode(data)
        if compressed:
            data = zlib.decompress(data)
        data = data.decode("utf-8")
    except Exception as e:
        raise DecodeError(
            f'Failed to decode cookie, are you sure '
            f'this was a Flask session cookie? {e}')
    def hook(obj):
        if len(obj) != 1:
            return obj
        key, val = next(iter(obj.items()))
        if key == ' t':
            return tuple(val)
        elif key == ' u':
            return UUID(val)
        elif key == ' b':
            return b64decode(val)
        elif key == ' m':
            return Markup(val)
        elif key == ' d':
            return parse_date(val)
        return obj
    try:
        return json.loads(data, object_hook=hook)
    except json.JSONDecodeError as e:
        raise DecodeError(
            f'Failed to decode cookie, are you sure '
            f'this was a Flask session cookie? {e}')
```

session.decode 方法在接收到传入的 Flask Session 后，首先以 `.` 号开头来判断是否为压缩的 Flask Session，如果为压缩的 Flask Session 则将开头的 `. ` 号去除，接着将 Flask Session 以 `.` 号进行分割来获取 Session Data ，最后进行 base64 解码。如果成功解码则说明目标使用的是 Flask Session 。

![在这里插入图片描述](https://img-blog.csdnimg.cn/829a077b85724c8fadbef035ecc3b192.png#pic_center)


## session.verify

```python
for i, key in enumerate(SECRET_KEYS):
    cracked = session.verify(session_cookie, key)
    if cracked:
        break
```

在 Python 代码中，session.verify 方法的作用为根据密钥去验证 Flask Session 的正确性，如果验证成功则说明是正确的密钥。因此，在 Go 语言中实现同等逻辑即可，具体需要下断点调试，从源码的角度查看 session.verify 的执行流程。

session.verify 方法的组成如图所示：

![在这里插入图片描述](https://img-blog.csdnimg.cn/774265f3429f490eab1f531197477c76.png#pic_center)


get_serializer(secret, legacy, salt)：

```python
def get_serializer(secret: str, legacy: bool, salt: str) -> URLSafeTimedSerializer:
    if legacy:
        signer = LegacyTimestampSigner
    else:
        signer = TimestampSigner
    return URLSafeTimedSerializer(
        secret_key=secret,
        salt=salt,
        serializer=TaggedJSONSerializer(),
        signer=signer,
        signer_kwargs={
            'key_derivation': 'hmac',
            'digest_method': hashlib.sha1})
```

get_serializer 方法的作用为返回一个 URLSafeTimedSerializer 的构造方法，其中的 secret  和 salt 参数是由session.verify(session_cookie, key) 传入的 。

在 signer_kwargs 参数中包含了两个键值对（key-value pair）：

1. 'key_derivation': 'hmac'：这是字典中的第一个键值对。它将键 key_derivation 映射到值 hmac。这表示在某个上下文中，使用 HMAC（Hash-based Message Authentication Code）作为密钥派生方法。
2. 'digest_method': hashlib.sha1：这是字典中的第二个键值对。它将键 digest_method 映射到值 hashlib.sha1。这表示在某个上下文中，使用 SHA-1 哈希算法作为摘要方法。

**因此 Flask Session 使用 HMAC 算法作为密钥派生方法，使用 SHA-1 哈希算法作为摘要方法。**

loads(value) 方法使用了 signer.unsign 方法，其中参数 s 为传入的 session 值：

![在这里插入图片描述](https://img-blog.csdnimg.cn/dc9d7b8dce0149a5880335e3d7addd7f.png#pic_center)


跟进调试 signer.unsign(s, max_age=max_age, return_timestamp=True) 发现调用了 super().unsign(signed_value) ，此时 signed_value 的值为 Flask Session ：

![在这里插入图片描述](https://img-blog.csdnimg.cn/54b29375121d44598c72cadc57e5a529.png#pic_center)


进入 super().unsign 方法调试可以发现 sig 变量为 Flask Session 组成结构中的 Cryptographic Hash ，value 变量为 Flask Session 组成结构中的  Session Data + "." + Timestamp ：

![在这里插入图片描述](https://img-blog.csdnimg.cn/28f42111e5b2493081ba44de33e3bd26.png#pic_center)


至此，我们成功得知 Flask Session 结构中的 Session Data 和 Timestamp 是如何划分的，接下来我们需要得知 Flask Session 是如何进行校验的，重点在 self.verify_signature(value,sig) 方法上：

![在这里插入图片描述](https://img-blog.csdnimg.cn/0b5cb6aed8af4dfaae231190ce2e72ae.png#pic_center)


进入 self.verify_signature(value,sig) 方法进行调试：

```python
def verify_signature(self, value: _t_str_bytes, sig: _t_str_bytes) -> bool:
    """Verifies the signature for the given value."""
    try:
        sig = base64_decode(sig)
    except Exception:
        return False

    value = want_bytes(value)

    for secret_key in reversed(self.secret_keys):
        key = self.derive_key(secret_key)

        if self.algorithm.verify_signature(key, value, sig):
            return True

    return False
```

主要分为两部分：

```python
1. self.derive_key()
2. self.algorithm.get_signature(key, value)	
```

- 第一部分为  self.derive_key() 方法：

  前面分析 get_serializer(secret, legacy, salt) 得知 Flask Session 使用的是 HMAC 算法，所以  self.derive_key() 方法的作用为使用 secret_key 创建一个 HMAC 对象，使用 sha1 作为摘要算法，接着向 HMAC 对象中添加 self.salt 数据，在 Flask 中默认为 cookie-session ，最后返回 HMAC 对象的摘要，即 mac.digest() 的结果，也就是第二部分 self.algorithm.get_signature(key, value) 方法中的参数 key 。

![在这里插入图片描述](https://img-blog.csdnimg.cn/29233556cc8a4b4193e523c06a370127.png#pic_center)


- 第二部分为 self.algorithm.get_signature(key, value) 方法：

  ```python
  def verify_signature(self, key: bytes, value: bytes, sig: bytes) -> bool:
          """Verifies the given signature matches the expected
          signature.
          """
          return hmac.compare_digest(sig, self.get_signature(key, value))
  ```

  此时的 hmac.compare_digest(sig, self.get_signature(key,value)) 使用了 self.get_signature(key,value) 方法：

![在这里插入图片描述](https://img-blog.csdnimg.cn/62ae7559e69c4139b0d02a1375f0482f.png#pic_center)


​     该方法的作用为使用给定的密钥和消息数据来生成一个 HMAC 签名，以帮助确保数据的完整性和真实性。此时的密钥为第一部分      self.derive_key() 方法的执行结果，消息数据为 Flask Session 组成结构中的  Session Data + "." + Timestamp 。最后将生成的 HMAC 签名和第一部分 self.derive_key() 方法生成的 key 使用 hmac.compare_digest 进行比较，当两个值完全相同时该密钥则为正确密钥。

![在这里插入图片描述](https://img-blog.csdnimg.cn/6beb9e7e256c4bf8b32b920884a8bb6c.png#pic_center)


## session.sign 

```python
forged_cookie = session.sign({'_user_id': 1, 'user_id': 1}, key)
```

在 Python 代码中，session.sign 方法的作用为根据密钥和 Session Data 生成 Flask Session。因此，在 Go 语言中实现同等逻辑即可，具体需要下断点调试，从源码的角度查看 session.sign 的执行流程。

session.sign 方法的组成如图所示：

![在这里插入图片描述](https://img-blog.csdnimg.cn/eb107305b1a34096a630f0426ecd1c48.png#pic_center)


get_serializer 方法在实现 session.verify 方法中已分析。因此，主要查看 dumps(value) 方法，可以得知主要调用了 self.mak_signer(salt).sign(payload) ，而此时 payload 已经被 base64 编码：

![在这里插入图片描述](https://img-blog.csdnimg.cn/a2d79796a2aa4ec5a8bfbb1fa92bcfa1.png#pic_center)


这里将分两部分进行解析：

- 第一部分 make_signer：

![在这里插入图片描述](https://img-blog.csdnimg.cn/366679bd7aec42f3a13c08446d29f35d.png#pic_center)


make_signer 为构造方法，依据传入的参数对 self.signer 进行初始化赋值。

- 第二部分 .sign(payload) ：

`{'_user_id': 1, 'user_id': 1}` 已经在 dumps(value) 方法中被 base64 编码了，即 Flask Session 组成结构中的  Session Data，而 timestamp 为当前时间戳的 base64 编码。

![在这里插入图片描述](https://img-blog.csdnimg.cn/00da732802494ad3999c3e4b22d6c089.png#pic_center)


此时将 Session Data + "." + Timestamp 作为 self.get_signature 方法的参数（ self.get_signature 方法在实现 session.verify 方法中已解析），生成为 Flask Session 组成结构中的 Cryptographic Hash：

![在这里插入图片描述](https://img-blog.csdnimg.cn/e2df54f64e1e486e8fdc455db26c5ec7.png#pic_center)


最后将 Flask Session 组成结构中的 Session Data、Timestamp、Cryptographic Hash以`.`号进行拼接为最终的 Flask Session 。

![在这里插入图片描述](https://img-blog.csdnimg.cn/9b49c514876c4a0bacc80ca0381593d9.png#pic_center)


综上，我们成功分析完 Flask Session 的校验、生成过程，接下来以 Apache Superset 权限绕过漏洞（CVE-2023-27524）为例，实现效果如下：

![在这里插入图片描述](https://img-blog.csdnimg.cn/9e70ebdbe8834d6eb7ea1d3fa67df459.gif#pic_center)


# 总结

在白帽汇安全研究院，漏洞检测和利用是一项创造性的工作，我们致力于以最简洁，高效的方式来实现。为了在 Goby 中实现 Flask Session 生成和利用方法，我们花费大量精力去调试 Flask 源码，分析 Session 的构造过程。最终，我们成功在 Go 语言中实现了 Flask Session 校验和生成方法。为了验证方法的可靠性，我们以 Apache Superset 权限绕过漏洞（CVE-2023-27524）为例，在 Goby 上实现了漏洞攻击效果，并加入了一键获取数据库凭据，一键反弹 shell 的利用方式。

# 参考

[https://github.com/horizon3ai/CVE-2023-27524/blob/main/CVE-2023-27524.py](https://github.com/horizon3ai/CVE-2023-27524/blob/main/CVE-2023-27524.py)

[https://www.horizon3.ai/cve-2023-27524-insecure-default-configuration-in-apache-superset-leads-to-remote-code-execution/](https://www.horizon3.ai/cve-2023-27524-insecure-default-configuration-in-apache-superset-leads-to-remote-code-execution/)

[https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)

[https://github.com/search?q=Flask&type=repositories](https://github.com/search?q=Flask&type=repositories)
<br/>

Goby 官网: https://gobysec.net/
如果您有任何反馈建议，您可通过提交 issue 或是以下方式联系我们：
GitHub issue: https://github.com/gobysec/Goby/issues
微信群：关注公众号“GobySec“，回复暗号”加群“ （社群优势：可第一时间了解Goby功能发布、活动等咨询）
Telegram Group: http://t.me/gobies
推特：https://twitter.com/GobySec
