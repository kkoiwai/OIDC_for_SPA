 # OIDC Login SPA demo

## About

very simple implementation of tri-party (Browser - RP - IDP) OIDC login

## Try it

https://oidc-for-spa.glitch.me/

## How to use this

1. Setup OIDC (ex. Google Login)
2. open app.js and edit SETTINGS
3. open console and type following commands

```
$ npm install
$ node app.js
```
4. open browser and goto http://localhost:3030

## Author

Kosuke Koiwai (https://github.com/kkoiwai)

## Details (in Japanese)

OpenID Connectの仕組みを使って、Single Page Application (SPA) っぽくログインするデモです。
HTMLそのものは1つのみ、かつすべて静的に生成されており、アプリサーバとajaxで通信してログイン処理を行います。
OIDCはinplicitやhybrindフローではなく、codeフローとなっており、リダイレクトで受信した認可コードも、サーバではなくブラウザ側で取得してからajaxでサーバに送信する作りとしています。
そのため、HTMLの動きを参考にすることで、ネイティブアプリも同様に実装できます。

ただし、あくまでOIDCの動作デモとして作成しているため、エラー処理が完全ではないこと、仕様の完全準拠や安全性を保証するものではありません。

詳細はQiitaをご参照ください。 (https://qiita.com/kkoiwai/items/3e1205bf60b11c8d9649)
