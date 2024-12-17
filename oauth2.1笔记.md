# 一、登陆相关知识及遇到的问题

## 一、知识

### 1、前端VUE实现登录

https://www.makerhu.com/posts/78e35d03/

### 2、java注册nacos

**参考官方项目**：https://github.com/alibaba/spring-cloud-alibaba/wiki/Nacos-discovery

1、首先下载nacos：https://github.com/alibaba/nacos/releases

2、解压缩后在bin文件目录下输入cmd调出命令行

![image-20241119105529309](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241119105529309.png)

3、输入以下命令在本地打开nacos

```
startup.cmd -m standalone
```

4、输入返回的网址打开nacos

![image-20241119105838113](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241119105838113.png)

5、在父项目中加入依赖，由于此处使用的是springboot3.3，故使用2023.0.1.3版本

```
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.alibaba.cloud</groupId>
            <artifactId>spring-cloud-alibaba-dependencies</artifactId>
            <version>2023.0.1.3</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>
```

6、在想要注册nacos的项目中引入依赖

```
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
</dependency>
```

7、在Application开始文件处加上注解

```
@EnableDiscoveryClient
```

8、在application.yml文件中加入

```
spring:
  cloud:
    nacos:
      discovery:
        server-addr: 127.0.0.1:8848
```

### 3、跨域处理

```
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 应用于所有路径
                .allowedOriginPatterns("http://locahost:8080") // 允许的源
                .allowedMethods("GET", "POST", "PUT", "DELETE") // 允许的HTTP方法
                .allowedHeaders("*") // 允许的请求头
                .allowCredentials(true); // 是否允许携带凭证（如Cookies）
    }
}
```

### 二、实现

1、首先引入依赖：

```
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
        </dependency>
 <!-- 添加spring security cas支持。这里需添加spring-security-cas依赖，
否则启动时报java.lang.ClassNotFoundException: org.springframework.security.cas.jackson2.CasJackson2Module错误。
-->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-cas</artifactId>
        </dependency>
```

2、AuthorizationConfig文件

```

/* https://www.youtube.com/watch?v=HdSktctSplc 参考视频*/

/**
 * 认证配置
 * 在Spring Security 6.0版本中将@Configuration注解从@EnableWebSecurity, @EnableMethodSecurity, @EnableGlobalMethodSecurity和 @EnableGlobalAuthentication 中移除，使用这些注解需手动添加 @Configuration 注解
 * {@link EnableWebSecurity} 注解有两个作用:
 * 1. 加载了WebSecurityConfiguration配置类, 配置安全认证策略。
 * 2. 加载了AuthenticationConfiguration, 配置了认证信息。
 */
@Configuration
@EnableWebSecurity
public class AuthorizationConfig {

    @Autowired
    //此处需要自己重写实现该类里loadUserByUsername()的方法
    private UserDetailsService userDetailsService;

    @Bean
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        //将自定义converter和provider存入tokenEndpoint
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenRequestConverter(new EmailCodeGrantAuthenticationConverter())
                .authenticationProvider(new EmailCodeGrantAuthenticationProvider(authorizationService, tokenGenerator)));
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenRequestConverter(new PasswordCodeGrantAuthenticationConverter())
                .authenticationProvider(new PasswordcodeGrantAuthenticationProvider(authorizationService, tokenGenerator, userDetailsService, passwordEncoder())));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http.securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .apply(authorizationServerConfigurer);

        return http.build();
    }

    /**
     * 配置密码解析器，使用BCrypt的方式对密码进行加密和验证
     *
     * @return BCryptPasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*将clientid、clientsecret都保存进数据库里，如果都保存了，就没必要再读取存储一遍了*/
    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        // 基于db存储客户端
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
    /*    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("weblogin-client")
                .clientSecret(passwordEncoder.encode("weblogin-client123456"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(new AuthorizationGrantType(SecurityConstants.GRANT_TYPE_EMAIL_CODE))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .scope("message.write")
                .scope("openid")
                // 授权码模式回调地址，oauth2.1已改为精准匹配，不能只设置域名，并且屏蔽了localhost，本机使用127.0.0.1访问
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .build();

        // 初始化客户端
        RegisteredClient repositoryByClientId = registeredClientRepository.findByClientId(registeredClient.getClientId());
        if (repositoryByClientId == null) {
            registeredClientRepository.save(registeredClient);
        }*/
        return registeredClientRepository;
    }

    @Bean
    OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
        JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
        jwtGenerator.setJwtCustomizer(jwtCustomizer());
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    //toeknGenerator的配置，在这里可以将想要使用token返回的参数存进去，比如用户信息
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
//            JwsHeader.Builder headers = context.getJwsHeader();

            JwtClaimsSet.Builder claims = context.getClaims();
            if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
                // Customize headers/claims for access_token
                JwtClaimsSet build = claims.build();
                Map<String, Object> claims2 = build.getClaims();
                Object sub = claims2.get("sub");
                UserDetails userDetails = userDetailsService.loadUserByUsername(sub.toString());
                LoginUser loginUser = new LoginUser();
                BeanUtils.copyProperties(userDetails, loginUser);
                claims.claim("userInfo", loginUser);
            } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                // Customize headers/claims for id_token

            }
        };
    }

    //此处设置静态页面过滤及权限过滤
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                        // 放行静态资源
                        .requestMatchers("/assets/**", "/webjars/**", "/login/**").permitAll()
                        .anyRequest().authenticated()
                )
                // 指定登录页面
                .formLogin(formLogin ->
                        formLogin.loginPage("/login")
                );
        // 添加BearerTokenAuthenticationFilter，将认证服务当做一个资源服务，解析请求头中的token
        http.oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults())
                        //添加authorization认证授权失败的回调
                        .accessDeniedHandler(SecurityUtils::exceptionHandler)
                        .authenticationEntryPoint(SecurityUtils::exceptionHandler)
                // Accept access tokens for User Info and/or Client Registration
        );
        return http.build();
    }
```

3、自定义AuthenticationConverter

```
public class PasswordCodeGrantAuthenticationConverter implements AuthenticationConverter {

    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://baidu.com";

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!SecurityConstants.GRANT_TYPE_PASSWORD_CODE.equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        MultiValueMap<String, String> parameters = getParameters(request);

        // scope (OPTIONAL)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    "OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE,
                    ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(
                    Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new PasswordCodeGrantAuthenticationToken(new AuthorizationGrantType(SecurityConstants.GRANT_TYPE_PASSWORD_CODE), clientPrincipal,requestedScopes, additionalParameters);
    }

    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }

}
```

### 三、问题

### 1、jwt如何在未到到期时间之前就使其无法验证，用于用户注销等实际功能

因为jwt拥有无需存在服务器的优势，所以我们尽量不将jwt存储在服务器里。第一种方式是设置jwt过期时间短一些，刷新token时间长一些，这样即使客户端token被删除，而用户私自保存，jwt也会很快过期。第二种方式是创建jwt黑名单，每次请求都会先根据当前jwt查redis服务器，如果存在redis里，就是理论上应该注销了的不能使用的jwt，此时不可请求通过，这种方式在保存jwt时，将redis的过期时间存储为jwt的过期时间，这样在jwt过期时redis中也不会再有它的存在了。

### 2、跨包调用方法报错A component required a bean of type ‘xxx‘ that could not be found.

@MainInterface自己写的注解，com.kn.core包里的UserUtil需要用@Component放入spring容器中进行管理，因此在其他包里需要扫描这个包，也就需要加一个注解，如果不加这个注解，直接@ComponentScan扫描，就只能扫描到core包，没法扫描自己的包了。

```
1、@Import({MainConfig.class})
2、
@ComponentScan({"com.kn.core"})
public class MainConfig {
    public MainConfig() {
    }
}
```

### 3、此处需要写开启了oauth2服务的地址，而不是自己项目的地址

```
security:
  oauth2:
    resourceserver:
      jwt:
        issuer-uri: http://localhost:9019
```

### 4、其他项目的SecurityConfig配置，一定要加.jwt(Customizer.withDefaults()));否则会报错

```
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //此处设置静态页面过滤及权限过滤
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize
                // 放行静态资源
                .requestMatchers("/assets/**", "/webjars/**", "/login/**", "test3").permitAll()
                .anyRequest().authenticated()
        );
        // 添加BearerTokenAuthenticationFilter，将认证服务当做一个资源服务，解析请求头中的token
        http.oauth2ResourceServer((resourceServer) -> resourceServer
                .jwt(Customizer.withDefaults()));
        return http.build();
    }
}
```

### 5、本地服务通过feign调用登录时，此jwt的claim的iss不对，从localhost:9019变成ip+9019,所以在生成token设置claim处，将iss改成了本地端口

```
claims.claim("iss", "http://localhost:9019");
```

### 6、同时有password和email两个拓展登录方式，只会获取第一个provider

在每一个provider，转换authentication时，如果转换失败，就要return null，才会到下一个provider

```
EmailCodeGrantAuthenticationToken authenticationToken = null;
try {
    authenticationToken =
            (EmailCodeGrantAuthenticationToken) authentication;
} catch (Exception e) {
    return null;
}
```

### 7、OIDC

https://koca.szkingdom.com/forum/t/topic/139

### 8、springboot6以后，没有@Type(type=)

```
 //@JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "imgpath",columnDefinition = "TEXT")
    private String imgPath;
```

### 9、前端vue下载node.js报错npm ERR! code CERT_HAS_EXPIRED

通常是因为您的本地计算机上的根证书已过期。这个错误可能是由于您的操作系统或Node.js环境中的证书问题导致的。

解决方法

        1、清除npm缓存
        npm cache clean --force

```
2、手动设置npm镜像源：有时，npm的默认镜像源可能会出现证书问题。您可以尝试切换到另一个镜像源，例如使用淘宝镜像。可以通过以下命令来设置：
npm config set registry https://registry.npmmirror.com/
```

如果执行完以上命令还未解决，可以再尝试以下方法

        3、更新npm和Node.js：尝试更新npm到最新版本。有时候，旧版本的npm可能会因为证书过期而无法正常工作。您可以使用以下命令来更新npm：
        
    npm install -g npm@latest

```
4、更新操作系统：有时候，如果系统时间不正确，可能会导致SSL证书认证失败。因此，请确保您的系统时间设置正确。您可以使用以下命令来同步系统时间：

sudo ntpdate -u time.nist.gov
```

### 10、vue : 无法加载文件 C:\Users\Administrator\AppData\Roaming\npm\vue.ps1，因为在此系统上禁止运行脚本

https://blog.csdn.net/Hc_is_only/article/details/131278144

### 11、gateway

https://www.linkedin.com/pulse/spring-cloud-gateway-using-virtual-threads-young-gyu-kim-zpoxc/?trk=article-ssr-frontend-pulse_little-text-block
