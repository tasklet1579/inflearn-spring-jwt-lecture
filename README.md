# Spring Boot JWT Tutorial

## Author

**SilverNine**

* https://silvernine.me
* https://portfolio.silvernine.me
* https://github.com/silvernine

## Copyright and license

The code is released under the [MIT license](LICENSE?raw=true).

## 강의 내용

<details>
<summary>✍️ 1. JWT 소개</summary>

JWT 정의
- JWT는 RFC 7519 웹 표준으로 지정되어 있고 Json 객체를 사용해서 정보들을 저장하고 있는 Web Token이다.

JWT 구조
- JWT는 Header, Payload, Signature로 구성되어 있다.
  - Header : Signature를 해싱하기 위한 알고리즘 정보들이 담겨 있다.
  - Payload : 서버와 클라이언트가 시스템에서 실제로 사용되는 정보들이 담겨 있다.
  - Signature : Token의 유효성 검증을 위한 암호화된 문자열이다. 이 문자열을 통해 서버에서는 유효한 Token인지 검증할 수 있다.

💡 JWT 장점
- 중앙의 인증 서버와 데이터 스토어에 대한 의존성이 없기 때문에 수평 확장이 용이하다.
- Base64 URL-Safe 인코딩을 이용하기 때문에 URL, Cookie, Header 어디에서든 사용할 수 있는 범용성을 가지고 있다.

JWT 단점
- 토큰 내부에 정보가 저장되기 때문에 노출되면 안되는 정보를 저장하는 실수를 범할 수 있다.
- 저장하는 정보가 많아지면 트래픽 크기가 커질 수 있다.
- 토큰이 서버에 저장되지 않고, 각 클라이언트에 저장되기 때문에 서버에서 각 클라이언트에 저장된 토큰 정보를 직접 조작할 수 없다.

</details>
