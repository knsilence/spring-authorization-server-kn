package com.kn.system.controller;

import com.kn.core.common.UserUtils;
import com.kn.core.model.LoginUser;
import com.kn.system.client.AuthClient;
import jakarta.annotation.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class TestController {

    @Resource
    private UserUtils userUtils;
    @Resource
    private AuthClient authClient;

    @GetMapping("/user")
    public Object user() {
        LoginUser loginUser = userUtils.loginUser();
        return loginUser;
    }

    @GetMapping("/test2")
    public Object tst() {
        return authClient.test();
    }

    @GetMapping("/test")
    public Object test() {
        return "hsh";
    }
}
