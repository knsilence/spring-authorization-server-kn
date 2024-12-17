package com.kn.auth.config;

import com.kn.auth.client.SendMsgClient;
import com.kn.auth.model.UserInfoModel;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.Assert;

import java.security.Principal;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

//TODO：待改
/*邮箱登录*/
public class EmailCodeGrantAuthenticationProvider implements AuthenticationProvider {

    private OAuth2AuthorizationService authorizationService;
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    private final UserDetailsService userDetailsService;
    private final SendMsgClient sendMsgClient;
    private final PasswordEncoder passwordEncoder;

    private String emailName = new String();
    private String emailCode = new String();
    private Set<String> authorizedScopes = new HashSet<>();

    public EmailCodeGrantAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator, UserDetailsService userDetailsService, SendMsgClient sendMsgClient, PasswordEncoder passwordEncoder) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.sendMsgClient = sendMsgClient;
    }

    //认证
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        EmailCodeGrantAuthenticationToken authenticationToken = null;
        try {
            authenticationToken =
                    (EmailCodeGrantAuthenticationToken) authentication;
        } catch (Exception e) {
            return null;
        }
        // Ensure the client is authenticated
        OAuth2ClientAuthenticationToken clientPrincipal =
                getAuthenticatedClientElseThrowInvalidClient(authenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        emailName = authenticationToken.getUsername();
        emailCode = authenticationToken.getPassword();
        authorizedScopes = authenticationToken.getScopes();


        // 确保注册认证中心（即自己建的数据表oauth2-register-client里包含当前的granttype）
        if (!registeredClient.getAuthorizationGrantTypes().contains(authenticationToken.getGrantType())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        // 确保注册认证中心（即自己建的数据表oauth2-register-client里包含当前的scope）
        authorizedScopes.forEach(scope -> {
            if (!registeredClient.getScopes().contains(scope)) {
                throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
            }
        });
        //校验账号密码或邮箱验证码
        UserInfoModel userInfoModel = null;
        try {
            userInfoModel = (UserInfoModel) userDetailsService.loadUserByUsername(emailName);
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }
        if ( !userInfoModel.getUsername().equals(emailName))
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);

        Boolean validEmailMsg = sendMsgClient.validEmailMsg(emailName, emailCode);
        if (!validEmailMsg)
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userInfoModel, null, userInfoModel.getAuthorities());

        // Generate the access token
        DefaultOAuth2TokenContext.Builder builder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthenticationToken)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(authenticationToken.getGrantType())
                .authorizationGrant(authenticationToken)
                .authorizedScopes(authorizedScopes);
        /*-------access-token-------------------*/
        OAuth2TokenContext tokenContext = builder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", null);
            throw new OAuth2AuthenticationException(error);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), null);
        // Initialize the OAuth2Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .authorizationGrantType(authenticationToken.getGrantType());
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(
                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) generatedAccessToken).getClaims())
            );
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        /*-------refresh-token-------------------*/
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
            tokenContext = builder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "The token generate failed to generate the refresh token", "");
                throw new OAuth2AuthenticationException(oAuth2Error);
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.attribute(Principal.class.getName(), usernamePasswordAuthenticationToken)
                .build();

        // Save the OAuth2Authorization
        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, usernamePasswordAuthenticationToken, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return EmailCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }


}