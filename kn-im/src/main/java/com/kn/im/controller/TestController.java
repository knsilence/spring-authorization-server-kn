package com.kn.im.controller;

import com.kn.core.common.UserUtils;
import com.kn.core.model.LoginUser;
import com.kn.im.client.AuthClient;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class TestController {

    @Resource
    private UserUtils userUtils;
    @Resource
    private AuthClient authClient;

    @GetMapping("/login/user")
    public Object user() {
        LoginUser loginUser = userUtils.loginUser();
        return loginUser;
    }

    @GetMapping("/test")
    public Object test() {
        return "loginUser";
    }

    @GetMapping("/test2")
    public Object test2() {
        return authClient.test();
    }
}
