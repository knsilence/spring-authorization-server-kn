package com.kn.auth.controller;

import com.kn.auth.pojo.UserInfo;
import com.kn.auth.service.TestService;
import com.kn.core.common.UserUtils;
import com.kn.core.model.LoginUser;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
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
        System.out.println("dd");
        return userInfo;

    }

/*    @Resource
    private UserUtils userUtils;

    @GetMapping("/login/user")
    public Object user() {
        LoginUser loginUser = userUtils.loginUser();
        return loginUser;
    }*/
}
