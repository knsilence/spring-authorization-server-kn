package com.kn.core.common;

import java.io.Serializable;

public class TokenInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    private String access_token;
    private String token_type;
    private String refresh_token;
    private String expires_in;

    public TokenInfo() {
    }

    public String getAccess_token() {
        return this.access_token;
    }

    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }

    public String getToken_type() {
        return this.token_type;
    }

    public void setToken_type(String token_type) {
        this.token_type = token_type;
    }

    public String getRefresh_token() {
        return this.refresh_token;
    }

    public void setRefresh_token(String refresh_token) {
        this.refresh_token = refresh_token;
    }

    public String getExpires_in() {
        return this.expires_in;
    }

    public void setExpires_in(String expires_in) {
        this.expires_in = expires_in;
    }

}
