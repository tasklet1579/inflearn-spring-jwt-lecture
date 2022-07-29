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
<br>

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

<details>
<summary>✍️ 2. Security 기본 설정, Data 설정</summary>
<br>

웹 보안 활성화
```
package edu.inflearn.jwt.config;

import ...

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/api/hello").permitAll()
            .anyRequest().authenticated();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
           .antMatchers(
                   "/h2-console/**",
                   "/favicon.ico",
                   "/error"
           );
    }
}
```

Entity 선언
```
package edu.inflearn.jwt.entity;

import ...

@Entity
@Table(name = "user")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {
    ...
    
    @ManyToMany
    @JoinTable(
            name = "user_authority",
            joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "user_id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
    private Set<Authority> authorities;
}
```

초기 데이터 적재
```
spring:

  ...

  jpa:
    database-platform: org.hibernate.dialect.H2Dialect
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        format_sql: true
        show_sql: true
    defer-datasource-initialization: true
```
</details>

<details>
<summary>✍️ 3. JWT</summary>
<br>

의존성 추가
```
dependencies {
    ...
    implementation group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.2'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.11.2'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.11.2'
}
```

프로퍼티 파일 수정
- HS512 알고리즘은 512bit의 digest를 생성하기 때문에 적어도 64byte 이상의 비밀키를 사용해야한다.
  - digest : 해시함수가 출력하는 결과
- echo '문자열'|base64
```
jwt:
  header: Authorization
  secret: c2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQtc2lsdmVybmluZS10ZWNoLXNwcmluZy1ib290LWp3dC10dXRvcmlhbC1zZWNyZXQK
  token-validity-in-seconds: 86400
```

웹 보안 추가 설정
```
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {    
    ...
    
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable한다.
                .csrf().disable()

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정한다.
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()
                .anyRequest().authenticated()

                .and()
                .apply(new JwtSecurityConfig(tokenProvider));
    }
}
```

🧰 TokenProvider
- InitializingBean
  - 스프링 프레임워크에 종속되는 인터페이스를 구현하는 방법이어서 컨테이너 외부에서 재사용할 수 없다.
```
package edu.inflearn.jwt.jwt;

import ...

@Component
public class TokenProvider implements InitializingBean {
    ...
    
    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }    
    
    public String createToken(Authentication authentication) {
        // Authentication 객체에 포함되어 있는 권한 정보들을 담은 토큰을 생성한다.
        ...
        
        return Jwts.builder()
                   .signWith(key, SignatureAlgorithm.HS512)
                   .setSubject(authentication.getName()) 
                   .claim(AUTHORITIES_KEY, authorities)
                   .setExpiration(validity)
                   .compact();
    }
    
    public Authentication getAuthentication(String token) {
        // 토큰에 담겨있는 권한 정보들을 이용해 Authentication 객체를 반환한다.
        ...
        
        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
    
    public boolean validateToken(String token) {
        // 토큰을 검증한다.
        ...
    }
}
```

🧰 JwtFilter
- GenericFilterBean
  - 기존 Filter에서 얻어올 수 없는 정보였던 Spring의 설정 정보를 가져올 수 있게 확장된 추상 클래스이다.
```
package edu.inflearn.jwt.jwt;

import ...

public class JwtFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        ...
        
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        
        filterChain.doFilter(servletRequest, servletResponse);      
    }
    
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

🧰 JwtSecurityConfig
```
package edu.inflearn.jwt.jwt;

public class JwtSecurityConfig 
        extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    ...
    
    @Override
    public void configure(HttpSecurity http) {
        JwtFilter customFilter = new JwtFilter(tokenProvider);
        http.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
```

🧰 JwtAuthenticationEntryPoint
- AuthenticationEntryPoint
  - 인증이 되지않은 유저가 요청을 했을때 동작한다.
```
package edu.inflearn.jwt.jwt;

import ...

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 유효한 자격증명을 제공하지 않고 접근하려 할때 401
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
```

🧰 JwtAccessDeniedHandler
- AccessDeniedHandler
  - 서버에 요청을 할 때 액세스가 가능한지 권한을 체크후 액세스 할 수 없는 요청을 했을시 동작한다.
```
package edu.inflearn.jwt.jwt;

import ...

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, 
                       HttpServletResponse response, 
                       AccessDeniedException accessDeniedException) throws IOException {
        //필요한 권한이 없이 접근하려 할때 403
        response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
}
```
</details>
