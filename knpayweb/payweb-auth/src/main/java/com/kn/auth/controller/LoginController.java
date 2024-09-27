package com.kn.auth.controller;

import com.kn.auth.pojo.UserInfo;
import com.kn.auth.service.TestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @Autowired
    private TestService testService;

    @GetMapping("/login/test")
    public Object test() {
        UserInfo userInfo = testService.find("11");
        return userInfo;

    }
}
