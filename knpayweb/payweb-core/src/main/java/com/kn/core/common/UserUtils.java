package com.kn.core.common;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kn.core.model.LoginUser;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
@Component
public class UserUtils {

    public UserUtils() {
    }

/*    public LoginUser loginUser(String access_token) {
        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(access_token);
        Map<String, Object> map = accessToken.getAdditionalInformation();

        try {
            String userobj = map.get("loginUser").toString();
            String destr = AESUtil.decrypt(userobj);
            ObjectMapper objectMapper = new ObjectMapper();
            LoginUser loginUser = (LoginUser)objectMapper.readValue(destr, LoginUser.class);
            return loginUser;
        } catch (Exception var8) {
            Exception e = var8;
            throw new Code500Exception(e.getMessage());
        }
    }*/

    public LoginUser loginUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth.getPrincipal() instanceof OidcUser) {
            OidcUser principal = ((OidcUser) auth.getPrincipal());
            System.out.println(principal.getClaims());
        }
        Jwt principal = (Jwt) auth.getPrincipal();
        Map<String, Object> claims = principal.getClaims();
        ObjectMapper objectMapper = new ObjectMapper();
        LinkedTreeMap userInfo = (LinkedTreeMap) claims.get("userInfo");
        HashMap<String, Object> hashMap = new HashMap<>(userInfo);
        LoginUser loginUser = new LoginUser();
        try {
            String s = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(hashMap);
            loginUser = (LoginUser) objectMapper.readValue(s, LoginUser.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return loginUser;
    }
}

