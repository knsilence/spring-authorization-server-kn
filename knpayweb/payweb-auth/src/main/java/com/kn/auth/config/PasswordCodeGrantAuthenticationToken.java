package com.kn.auth.config;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class PasswordCodeGrantAuthenticationToken extends AbstractAuthenticationToken {

    /**
     * ???ε???????scope
     */
    private final Set<String> scopes;

    /**
     * ???????????
     */
    private final Authentication clientPrincipal;

    /**
     * ???????????
     */
    private final Map<String, Object> additionalParameters;

    /**
     * ??????
     */
    private final AuthorizationGrantType authorizationGrantType;

    public PasswordCodeGrantAuthenticationToken(AuthorizationGrantType authorizationGrantType,
                                                Authentication clientPrincipal,
                                                @Nullable Set<String> scopes,
                                                @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        this.scopes = scopes;
        this.clientPrincipal = clientPrincipal;
        this.additionalParameters = additionalParameters;
        this.authorizationGrantType = authorizationGrantType;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return clientPrincipal;
    }

    /**
     * ?????????scope(s)
     *
     * @return ?????scope(s)
     */
    public Set<String> getScopes() {
        return this.scopes;
    }

    /**
     * ?????????е?authorization grant type
     *
     * @return authorization grant type
     */
    public AuthorizationGrantType getAuthorizationGrantType() {
        return this.authorizationGrantType;
    }

    /**
     * ?????????е???????
     *
     * @return ???????
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

}