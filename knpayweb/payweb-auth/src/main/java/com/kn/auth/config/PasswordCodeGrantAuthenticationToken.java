package com.kn.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class PasswordCodeGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

private static final long serialVersionUID = 1L;

    private final Set<String> scopes;

    private final String username;

    private final String password;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
//    private final Authentication clientPrincipal;

    /**
     * ???????????
     */
//    private final Map<String, Object> additionalParameters;

    /**
     * ??????
     */
//    private final AuthorizationGrantType authorizationGrantType;

    public PasswordCodeGrantAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                                Authentication clientPrincipal,
                                                @Nullable Set<String> scopes,
                                                @Nullable Map<String, Object> additionalParameters) {
        super(authorizationGrantType,clientPrincipal,additionalParameters);
        this.scopes = scopes;
//        this.clientPrincipal = clientPrincipal;
//        this.authorizationGrantType = authorizationGrantType;
        this.username= (String) additionalParameters.get(SecurityConstants.OAUTH_PARAMETER_PASSWORD_NAME);
        this.password= (String) additionalParameters.get(SecurityConstants.OAUTH_PARAMETER_PASSWORD_PASSWORD);
        if(this.scopes==null||this.scopes.isEmpty()){
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
        }
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    /*@Override
    public Object getPrincipal() {
        return clientPrincipal;
    }*/


    public Set<String> getScopes() {
        return this.scopes;
    }


/*    public AuthorizationGrantType getAuthorizationGrantType() {
        return this.authorizationGrantType;
    }*/

/*    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }*/
}