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

<details>
<summary>✍️ 4. 로그인</summary>
<br>

회원정보 조회
- @EntityGraph
  - Spring Data JPA에서 fetch join을 어노테이션으로 사용할 수 있도록 만든 기능이다.
    - fetch : attribute는 eager로 fetch하고 나머지 attribute는 lazy로 fetch한다.
    - load : attribute는 eager로 fetch하고 나머지 attribute는 entity에 명시한 type이나 default type으로 fetch한다.
```
package edu.inflearn.jwt.repository;

import ...

public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
```

UserDetailsService
```
package edu.inflearn.jwt.service;

import ...

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    ...

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) {
        // Database에서 User 정보를 권한 정보와 함께 가져온다.
        return userRepository.findOneWithAuthoritiesByUsername(username)
                             .map(user -> createUser(username, user))
                             .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
    }

    private org.springframework.security.core.userdetails.User createUser(String username, User user) {
        if (!user.isActivated()) {
            throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
        }
        List<GrantedAuthority> grantedAuthorities = user.getAuthorities()
                                                        .stream()
                                                        .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                                                        .collect(Collectors.toList());
        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),
                grantedAuthorities);
    }
}
```

🧪 HTTP Request
```
###
POST {{host}}/api/authenticate
Content-Type: application/json

{
  "username" : "admin",
  "password" : "admin"
}
```

🧪 HTTP Response
```
HTTP/1.1 200 
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTY1OTIzMTIxMn0.wZfhDUZrZ-lr6LTCeVE8rJnOOVk97cp5TMX4qbWro3zQA9KTCf_yjFS9PuCtK6zpdLIHhnx5sO5YT1h6WVWHAw
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: SAMEORIGIN
Content-Type: application/json
Transfer-Encoding: chunked
Date: Sat, 30 Jul 2022 01:33:32 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{
  "token": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJST0xFX0FETUlOLFJPTEVfVVNFUiIsImV4cCI6MTY1OTIzMTIxMn0.wZfhDUZrZ-lr6LTCeVE8rJnOOVk97cp5TMX4qbWro3zQA9KTCf_yjFS9PuCtK6zpdLIHhnx5sO5YT1h6WVWHAw"
}

Response code: 200; Time: 97ms; Content length: 203 bytes
```
</details>

<details>
<summary>✍️ 5. 권한</summary>
<br>

SecurityUtil
- JwtFilter 클래스의 doFilter 메소드에서 저장한 인증 정보에서 username을 반환한다.
```
package edu.inflearn.jwt.util;

import ...

public class SecurityUtil {
    ...

    public static Optional<String> getCurrentUsername() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        ...

        return Optional.ofNullable(username);
    }
}
```

UserService
- signup
  - 권한 객체와 유저 객체를 생성해서 데이터베이스에 저장한다.
- getUserWithAuthorities
  - username으로 유저의 정보와 권한을 반환한다.
- getMyUserWithAuthorities
  - context에 저장된 인증 정보로 유저의 정보와 권한을 반환한다.
```
package edu.inflearn.jwt.service;

import ...

@Service
public class UserService {
    ...

    @Transactional
    public User signup(UserDto userDto) {
        ...

        Authority authority = Authority.builder()
                                       .authorityName("ROLE_USER")
                                       .build();

        User user = User.builder()
                        ...
                        .authorities(Collections.singleton(authority))
                        .activated(true)
                        .build();

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getMyUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername()
                           .flatMap(userRepository::findOneWithAuthoritiesByUsername);
    }
}
```

UserController
- PreAuthorize
  - 요청이 들어와 메서드를 실행하기 전에 권한을 검사하는 어노테이션이다.
```
package edu.inflearn.jwt.controller;

import ...

@RestController
@RequestMapping("/api")
public class UserController {
    ...

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<User> getMyUserInfo() {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities().get());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<User> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username).get());
    }
}
```

🧪 HTTP Request
```
###
GET {{host}}/api/user/user
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyIiwiYXV0aCI6IlJPTEVfVVNFUiIsImV4cCI6MTY1OTQwNjQzNX0.fn4w59SCbiUWGfYWyqrJJp0udIHxizl2lRa1ifyocusuI2XKHTpRqLQYOwD9OZMF-_XBPjKLp9W7qe5ZI_QfBw
```

🧪 HTTP Response
```
GET http://localhost:8080/api/user/user

HTTP/1.1 403 
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: SAMEORIGIN
Content-Type: application/json
Transfer-Encoding: chunked
Date: Mon, 01 Aug 2022 02:30:08 GMT
Keep-Alive: timeout=60
Connection: keep-alive

{
  "timestamp": "2022-08-01T02:30:08.159+00:00",
  "status": 403,
  "error": "Forbidden",
  "trace": "org.springframework.security.access.AccessDeniedException: 접근이 거부되었습니다.\r\n\tat org.springframework.security.access.vote.AffirmativeBased.decide(AffirmativeBased.java:73)\r\n\tat org.springframework.security.access.intercept.AbstractSecurityInterceptor.attemptAuthorization(AbstractSecurityInterceptor.java:239)\r\n\tat org.springframework.security.access.intercept.AbstractSecurityInterceptor.beforeInvocation(AbstractSecurityInterceptor.java:208)\r\n\tat org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor.invoke(MethodSecurityInterceptor.java:58)\r\n\tat org.springframework.aop.framework.ReflectiveMethodInvocation.proceed(ReflectiveMethodInvocation.java:186)\r\n\tat org.springframework.aop.framework.CglibAopProxy$CglibMethodInvocation.proceed(CglibAopProxy.java:763)\r\n\tat org.springframework.aop.framework.CglibAopProxy$DynamicAdvisedInterceptor.intercept(CglibAopProxy.java:708)\r\n\tat edu.inflearn.jwt.controller.UserController$$EnhancerBySpringCGLIB$$a9af0928.getUserInfo(<generated>)\r\n\tat sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)\r\n\tat sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)\r\n\tat sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)\r\n\tat java.lang.reflect.Method.invoke(Method.java:498)\r\n\tat org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:205)\r\n\tat org.springframework.web.method.support.InvocableHandlerMethod.invokeForRequest(InvocableHandlerMethod.java:150)\r\n\tat org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod.invokeAndHandle(ServletInvocableHandlerMethod.java:117)\r\n\tat org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.invokeHandlerMethod(RequestMappingHandlerAdapter.java:895)\r\n\tat org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.handleInternal(RequestMappingHandlerAdapter.java:808)\r\n\tat org.springframework.web.servlet.mvc.method.AbstractHandlerMethodAdapter.handle(AbstractHandlerMethodAdapter.java:87)\r\n\tat org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:1070)\r\n\tat org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:963)\r\n\tat org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:1006)\r\n\tat org.springframework.web.servlet.FrameworkServlet.doGet(FrameworkServlet.java:898)\r\n\tat javax.servlet.http.HttpServlet.service(HttpServlet.java:655)\r\n\tat org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:883)\r\n\tat javax.servlet.http.HttpServlet.service(HttpServlet.java:764)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:227)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:162)\r\n\tat org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:53)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:189)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:162)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:327)\r\n\tat org.springframework.security.web.access.intercept.FilterSecurityInterceptor.invoke(FilterSecurityInterceptor.java:115)\r\n\tat org.springframework.security.web.access.intercept.FilterSecurityInterceptor.doFilter(FilterSecurityInterceptor.java:81)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.access.ExceptionTranslationFilter.doFilter(ExceptionTranslationFilter.java:122)\r\n\tat org.springframework.security.web.access.ExceptionTranslationFilter.doFilter(ExceptionTranslationFilter.java:116)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.session.SessionManagementFilter.doFilter(SessionManagementFilter.java:126)\r\n\tat org.springframework.security.web.session.SessionManagementFilter.doFilter(SessionManagementFilter.java:81)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.authentication.AnonymousAuthenticationFilter.doFilter(AnonymousAuthenticationFilter.java:109)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter.doFilter(SecurityContextHolderAwareRequestFilter.java:149)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.savedrequest.RequestCacheAwareFilter.doFilter(RequestCacheAwareFilter.java:63)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat edu.inflearn.jwt.jwt.JwtFilter.doFilter(JwtFilter.java:43)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:103)\r\n\tat org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:89)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.header.HeaderWriterFilter.doHeadersAfter(HeaderWriterFilter.java:90)\r\n\tat org.springframework.security.web.header.HeaderWriterFilter.doFilterInternal(HeaderWriterFilter.java:75)\r\n\tat org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.context.SecurityContextPersistenceFilter.doFilter(SecurityContextPersistenceFilter.java:110)\r\n\tat org.springframework.security.web.context.SecurityContextPersistenceFilter.doFilter(SecurityContextPersistenceFilter.java:80)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter.doFilterInternal(WebAsyncManagerIntegrationFilter.java:55)\r\n\tat org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)\r\n\tat org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:336)\r\n\tat org.springframework.security.web.FilterChainProxy.doFilterInternal(FilterChainProxy.java:211)\r\n\tat org.springframework.security.web.FilterChainProxy.doFilter(FilterChainProxy.java:183)\r\n\tat org.springframework.web.filter.DelegatingFilterProxy.invokeDelegate(DelegatingFilterProxy.java:354)\r\n\tat org.springframework.web.filter.DelegatingFilterProxy.doFilter(DelegatingFilterProxy.java:267)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:189)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:162)\r\n\tat org.springframework.web.filter.RequestContextFilter.doFilterInternal(RequestContextFilter.java:100)\r\n\tat org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:189)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:162)\r\n\tat org.springframework.web.filter.FormContentFilter.doFilterInternal(FormContentFilter.java:93)\r\n\tat org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:189)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:162)\r\n\tat org.springframework.web.filter.CharacterEncodingFilter.doFilterInternal(CharacterEncodingFilter.java:201)\r\n\tat org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:117)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:189)\r\n\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:162)\r\n\tat org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:197)\r\n\tat org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:97)\r\n\tat org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:541)\r\n\tat org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:135)\r\n\tat org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:92)\r\n\tat org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:78)\r\n\tat org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:360)\r\n\tat org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:399)\r\n\tat org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:65)\r\n\tat org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:890)\r\n\tat org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1789)\r\n\tat org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)\r\n\tat org.apache.tomcat.util.threads.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1191)\r\n\tat org.apache.tomcat.util.threads.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:659)\r\n\tat org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)\r\n\tat java.lang.Thread.run(Thread.java:748)\r\n",
  "message": "접근이 거부되었습니다.",
  "path": "/api/user/user"
}

Response code: 403; Time: 82ms; Content length: 10243 bytes
```
</details>
