package com.kn.auth.config;

import com.kn.auth.client.SendMsgClient;
import com.kn.core.model.LoginUser;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.kn.auth.util.SecurityUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Map;

import static org.springframework.web.servlet.function.RequestPredicates.headers;

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

    @Autowired
    private SendMsgClient sendMsgClient;

    @Bean
    SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            OAuth2AuthorizationService authorizationService,
            OAuth2TokenGenerator<?> tokenGenerator) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        //将自定义converter和provider存入tokenEndpoint
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenRequestConverter(new PasswordCodeGrantAuthenticationConverter())
                .authenticationProvider(new PasswordCodeGrantAuthenticationProvider(authorizationService, tokenGenerator, userDetailsService, passwordEncoder())));
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint.accessTokenRequestConverter(new EmailCodeGrantAuthenticationConverter())
                .authenticationProvider(new EmailCodeGrantAuthenticationProvider(authorizationService, tokenGenerator, userDetailsService, sendMsgClient, passwordEncoder())));
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
                .authorizationGrantType(new AuthorizationGrantType(GrantTypes.GRANT_TYPE_EMAIL_CODE))
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
                //TODO：此处很奇怪，本服务直接登录，就是http://localhost，从其他服务进行登陆生成jwt，此处iss就会变成此服务ip+端口。以后上线一定要改这个地方
                claims.claim("iss", "http://localhost:9019");
            } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
                // Customize headers/claims for id_token

            }
        };
    }

    //此处设置静态页面过滤及权限过滤
    /*Spring Security4默认是开启CSRF的，所以需要请求中包含CSRF的token信息，在其官方文档（参考资料1）中，提供了在form中嵌入一个hidden标签来获取token信息，其原理是，hidden标签使用了Spring Security4提供的标签，即${_csrf.parameterName}、${_csrf.token}， 后台页面渲染过程中，将此标签解所对应的值解析出来，这样，我们的form表单，就嵌入了Spring Security的所需的token信息，在后续的提交登录请求时，就不会出现没有CSRF token的异常。

另外，还有一个解决办法是，通过关闭CSRF来解决，这个几乎在任何场景中都能解决这个问题（上面这个解决方案，可能在某些渲染模板不能解析出来token值，不过可以通过后台程序来获取token值，然后自己定义变量来渲染到form中，这个也是可以的）。具体的做法是通过修改配置文件来关闭，我这里使用的是SpringBoot开发的项目，配置文件直接写在配置类中，通过.csrf().disable()来关闭，参考资料见二。不过这种方案，会迎来CSRF攻击，不建议在生产环境中使用，如果系统对外界做了隔离，这样做也是可以的。*/
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> {
                            try {
                                authorize
                                        // 放行静态资源
                                        .requestMatchers("/assets/**", "/webjars/**", "/login/**", "test").permitAll()
                                        .anyRequest().authenticated().and().csrf().disable();//关闭CSR;
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
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
}