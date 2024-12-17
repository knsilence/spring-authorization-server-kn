package com.kn.auth.controller;

import com.kn.auth.service.TestService;
import com.kn.core.common.UserUtils;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class LoginController {

    @Autowired
    private TestService testService;

    @Resource
    private UserUtils userUtils;

    @PostMapping("/test")
    public String test() {
        return "dd";
    }

    @GetMapping("/test2")
    public Object test2(@AuthenticationPrincipal OidcUser oidcUser)  {
        Map<String, Object> claims = oidcUser.getClaims();
        return null;
    }

}
