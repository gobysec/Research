

# Overview

Cross-language transplantation has always been a difficult problem to solve in the technical field, and the constraints between languages need to be solved. Fortunately, we have successfully used Go to implement IIOP protocol communication before, and we have learned from the past, so this time we will continue to use the cross-language method to implement Flask. Session forgery. This article takes the Apache Superset permission bypass vulnerability (CVE-2023-27524) as an example to describe how we implement the Session verification and generation functions of the Flask framework in Go.

In the end, we successfully used a cross-language method to detect and exploit the CVE-2023-27524 vulnerability in Goby, and added one-click acquisition of database credentials and one-click shell rebound:

![Insert picture description here](https://img-blog.csdnimg.cn/35fb0f3442554a938a535fe88ff83da2.gif#pic_center)


# Vulnerability principle

A session is a server-side managed data storage mechanism used to maintain persistent state information between users and web applications. It allows web applications to store and retrieve user-specific data between different HTTP requests.

When a user first accesses a web application, the server creates a unique session identifier for each user (usually a session ID or token), which is stored in a cookie in the user's browser or passed through a URL parameter. The server uses this ID to track a specific user's session.

**If we can create a Session with a privileged user, we can perform background dangerous operations, such as executing commands, uploading files, etc. **

In this example, Flask used by Apache Superset is a miniature Python Web framework that is used in many projects, such as Flask-Chat, Flask-Blog, Flask-Admin, etc. If the default Flask configuration is not changed, it may Causing potential vulnerabilities:



![Insert picture description here](https://img-blog.csdnimg.cn/91c00160605749799ee243010dcf4f08.png#pic_center)


The attacker first sends a login request packet, copies the Flask Session of the echo packet, and decodes the Session Data in the Session through the session.decode method. Secondly, use the session.verify method to verify whether the Flask Session uses the default key. If it is the default key, use the session.sign method to generate the corresponding Flask Session from the key and the decoded Session Data, thereby achieving the purpose of bypassing permissions.

Therefore, to use this permission to bypass the vulnerability, you need to understand the structure of Flask Session:

![Insert picture description here](https://img-blog.csdnimg.cn/98c45028f42244c09ae2da9486994110.png#pic_center)


The structure of Flask Session is mainly composed of three parts. The first part is Session Data, which is session data. The second part is Timestamp, which is the timestamp. The third part is Cryptographic Hash, which is the cryptographic hash. **Only Sessions that conform to the composition structure of Flask Session will be correctly parsed by Flask. **

# Flask Session

Since there is currently no ready-made Flask framework Session generation mechanism in the Go language, it is necessary to use Go to copy the core code of Flask Session as a final universal solution.

## session.decode

```python
     try:
         decoded = session.decode(session_cookie)
         print(f'Decoded session cookie: {decoded}')
     except:
         print('Error: Not a Flask session cookie')
         return
```

In Python code, the session.decode method is used to check whether the incoming Session value is a Flask Session. Therefore, the same logic can be implemented in the Go language. Specifically, it is necessary to set breakpoints for debugging and view the execution process of session.decode from the source code perspective.

The source code of the session.verify method is as follows:

```python
def decode(value: str) -> dict:
     try:
         compressed=False
         payload = value
         if payload.startswith('.'):
             compressed=True
             payload = payload[1:]
         data = payload.split(".")[0]
         data = base64_decode(data)
         if compressed:
             data = zlib.decompress(data)
         data = data.decode("utf-8")
     except Exception as e:
         raiseDecodeError(
             f'Failed to decode cookie, are you sure '
             f'this was a Flask session cookie? {e}')
     def hook(obj):
         if len(obj) != 1:
             return obj
         key, val = next(iter(obj.items()))
         if key == ' t':
             return tuple(val)
         elif key == 'u':
             return UUID(val)
         elif key == ' b':
             return b64decode(val)
         elif key == ' m':
             returnMarkup(val)
         elif key == ' d':
             return parse_date(val)
         return obj
     try:
         return json.loads(data, object_hook=hook)
     except json.JSONDecodeError as e:
         raiseDecodeError(
             f'Failed to decode cookie, are you sure '
             f'this was a Flask session cookie? {e}')
```

After receiving the incoming Flask Session, the session.decode method first determines whether it is a compressed Flask Session by starting with a `.` number. If it is a compressed Flask Session, the `.` number at the beginning will be removed, and then the Flask Session Split with `.` sign to obtain Session Data, and finally perform base64 decoding. If the decoding is successful, it means that the target is using Flask Session.

![Insert picture description here](https://img-blog.csdnimg.cn/829a077b85724c8fadbef035ecc3b192.png#pic_center)


## session.verify

```python
for i, key in enumerate(SECRET_KEYS):
     cracked = session.verify(session_cookie, key)
     if cracked:
         break
```

In the Python code, the function of the session.verify method is to verify the correctness of the Flask Session based on the key. If the verification is successful, it means that it is the correct key. Therefore, it is enough to implement the same logic in the Go language. Specifically, you need to set breakpoints for debugging and view the execution process of session.verify from the source code perspective.

The composition of the session.verify method is shown in the figure:

![Insert picture description here](https://img-blog.csdnimg.cn/774265f3429f490eab1f531197477c76.png#pic_center)


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

The function of the get_serializer method is to return a URLSafeTimedSerializer constructor, in which the secret and salt parameters are passed in by session.verify(session_cookie, key).

Two key-value pairs are included in the signer_kwargs parameter:

1. 'key_derivation': 'hmac': This is the first key-value pair in the dictionary. It maps the key key_derivation to the value hmac. This means that in a certain context, HMAC (Hash-based Message Authentication Code) is used as the key derivation method.
2. 'digest_method': hashlib.sha1: This is the second key-value pair in the dictionary. It maps the key digest_method to the value hashlib.sha1. This means that in a certain context, the SHA-1 hashing algorithm is used as the digest method.

**So Flask Session uses the HMAC algorithm as the key derivation method and the SHA-1 hashing algorithm as the digest method. **

The loads(value) method uses the signer.unsign method, where the parameter s is the incoming session value:

![Insert picture description here](https://img-blog.csdnimg.cn/dc9d7b8dce0149a5880335e3d7addd7f.png#pic_center)


Following up on the debugging signer.unsign(s, max_age=max_age, return_timestamp=True), we found that super().unsign(signed_value) was called, and the value of signed_value is Flask Session:

![Insert picture description here](https://img-blog.csdnimg.cn/54b29375121d44598c72cadc57e5a529.png#pic_center)


When debugging the super().unsign method, you can find that the sig variable is the Cryptographic Hash in the Flask Session composition structure, and the value variable is Session Data + "." + Timestamp in the Flask Session composition structure:

![Insert picture description here](https://img-blog.csdnimg.cn/28f42111e5b2493081ba44de33e3bd26.png#pic_center)


At this point, we have successfully learned how Session Data and Timestamp in the Flask Session structure are divided. Next, we need to know how Flask Session is verified, focusing on the self.verify_signature(value,sig) method:

![Insert picture description here](https://img-blog.csdnimg.cn/0b5cb6aed8af4dfaae231190ce2e72ae.png#pic_center)


Enter the self.verify_signature(value,sig) method for debugging:

```python
def verify_signature(self, value: _t_str_bytes, sig: _t_str_bytes) -> bool:
     """Verifies the signature for the given value."""
     try:
         sig = base64_decode(sig)
     exceptException:
         return False

     value = want_bytes(value)

     for secret_key in reversed(self.secret_keys):
         key = self.derive_key(secret_key)

         if self.algorithm.verify_signature(key, value, sig):
             return True

     return False
```

Mainly divided into two parts:

```python
1. self.derive_key()
2. self.algorithm.get_signature(key, value)
```

- The first part is the self.derive_key() method:

   From the previous analysis of get_serializer(secret, legacy, salt), we learned that Flask Session uses the HMAC algorithm, so the function of the self.derive_key() method is to use secret_key to create an HMAC object, use sha1 as the digest algorithm, and then add self to the HMAC object. .salt data, which defaults to cookie-session in Flask, finally returns the digest of the HMAC object, which is the result of mac.digest(), which is the parameter key in the self.algorithm.get_signature(key, value) method in the second part.

![Insert picture description here](https://img-blog.csdnimg.cn/29233556cc8a4b4193e523c06a370127.png#pic_center)


- The second part is the self.algorithm.get_signature(key, value) method:

   ```python
   def verify_signature(self, key: bytes, value: bytes, sig: bytes) -> bool:
           """Verifies the given signature matches the expected
           signature.
           """
           return hmac.compare_digest(sig, self.get_signature(key, value))
   ```

   At this time, hmac.compare_digest(sig, self.get_signature(key,value)) uses the self.get_signature(key,value) method:

![Insert picture description here](https://img-blog.csdnimg.cn/62ae7559e69c4139b0d02a1375f0482f.png#pic_center)


This method generates an HMAC signature using the given key and message data to help ensure the integrity and authenticity of the data. The key at this time is the execution result of the self.derive_key() method in the first part, and the message data is Session Data + "." + Timestamp in the Flask Session composition structure. Finally, the generated HMAC signature and the key generated by the self.derive_key() method in the first part are compared using hmac.compare_digest. When the two values ​​are exactly the same, the key is the correct key.

![Insert picture description here](https://img-blog.csdnimg.cn/6beb9e7e256c4bf8b32b920884a8bb6c.png#pic_center)


## session.sign

```python
forged_cookie = session.sign({'_user_id': 1, 'user_id': 1}, key)
```

In Python code, the session.sign method generates a Flask Session based on the key and Session Data. Therefore, it is enough to implement the same logic in the Go language. Specifically, you need to set breakpoints for debugging and view the execution process of session.sign from the source code perspective.

The composition of the session.sign method is shown in the figure:

![Insert picture description here](https://img-blog.csdnimg.cn/eb107305b1a34096a630f0426ecd1c48.png#pic_center)


The get_serializer method has been analyzed in the implementation of the session.verify method. Therefore, mainly looking at the dumps(value) method, we can know that self.mak_signer(salt).sign(payload) is mainly called, and at this time the payload has been base64 encoded:

![Insert picture description here](https://img-blog.csdnimg.cn/a2d79796a2aa4ec5a8bfbb1fa92bcfa1.png#pic_center)


This will be analyzed in two parts:

- Part 1 make_signer:

![Insert picture description here](https://img-blog.csdnimg.cn/366679bd7aec42f3a13c08446d29f35d.png#pic_center)


make_signer is a constructor method that initializes and assigns self.signer according to the parameters passed in.

- The second part .sign(payload):

`{'_user_id': 1, 'user_id': 1}` has been base64 encoded in the dumps(value) method, that is, the Session Data in the Flask Session composition structure, and timestamp is the base64 encoding of the current timestamp.

![Insert picture description here](https://img-blog.csdnimg.cn/00da732802494ad3999c3e4b22d6c089.png#pic_center)


At this time, Session Data + "." + Timestamp are used as parameters of the self.get_signature method (the self.get_signature method has been parsed in the implementation of the session.verify method) and generated as a Cryptographic Hash in the Flask Session composition structure:

![Insert picture description here](https://img-blog.csdnimg.cn/e2df54f64e1e486e8fdc455db26c5ec7.png#pic_center)


Finally, the Session Data, Timestamp, and Cryptographic Hash in the Flask Session composition structure are spliced with `.` signs to form the final Flask Session.

![Insert picture description here](https://img-blog.csdnimg.cn/9b49c514876c4a0bacc80ca0381593d9.png#pic_center)


In summary, we have successfully analyzed the verification and generation process of Flask Session. Next, we will take the Apache Superset permission bypass vulnerability (CVE-2023-27524) as an example. The implementation effect is as follows:

![Insert picture description here](https://img-blog.csdnimg.cn/9e70ebdbe8834d6eb7ea1d3fa67df459.gif#pic_center)


# Summarize

At BaiHaoHui Security Research Institute, vulnerability detection and exploitation is a creative work, and we are committed to achieving it in the most concise and efficient way. In order to implement Flask Session generation and utilization methods in Goby, we spent a lot of energy debugging the Flask source code and analyzing the Session construction process. Finally, we successfully implemented the Flask Session checksum generation method in the Go language. In order to verify the reliability of the method, we took the Apache Superset permission bypass vulnerability (CVE-2023-27524) as an example, implemented the vulnerability attack effect on Goby, and added one-click acquisition of database credentials and one-click rebound shell. .

# refer to

[https://github.com/horizon3ai/CVE-2023-27524/blob/main/CVE-2023-27524.py](https://github.com/horizon3ai/CVE-2023-27524/blob/main/ CVE-2023-27524.py)

[https://www.horizon3.ai/cve-2023-27524-insecure-default-configuration-in-apache-superset-leads-to-remote-code-execution/](https://www.horizon3.ai /cve-2023-27524-insecure-default-configuration-in-apache-superset-leads-to-remote-code-execution/)

[https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)

[https://github.com/search?q=Flask&type=repositories](https://github.com/search?q=Flask&type=repositories)
<br/>

Goby official website: https://gobysec.net/
If you have any feedback or suggestions, you can submit an issue or contact us in the following ways:
GitHub issue: https://github.com/gobysec/Goby/issues
WeChat group: Follow the public account "GobySec" and reply with the secret code "Join the group" (Community advantage: you can learn about Goby function releases, activities and other consultations at the first time)
Telegram Group: http://t.me/gobies
Twitter: https://twitter.com/GobySec
