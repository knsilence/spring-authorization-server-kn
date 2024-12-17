package com.kn.system.controller;

import com.kn.core.common.UserUtils;
import com.kn.core.model.LoginUser;
import com.kn.core.result.BaseResultModel;
import com.kn.core.result.DefaultResultModel;
import com.kn.system.client.AuthClient;
import com.kn.system.model.LoginModel;
import com.kn.system.service.LoginService;
import jakarta.annotation.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;


@RestController
public class LoginController {

    private static final String webClient = "weblogin-knsystem";
    private static final String webSecret = "webkn-128907563";
    @Resource
    private UserUtils userUtils;
    @Resource
    private AuthClient authClient;
    @Resource
    private LoginService loginService;

    private String getWindowsCredentials() {
        String credentials = Base64.getEncoder().encodeToString((webClient + ":" + webSecret).getBytes());
        return "Basic " + credentials;

    }

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


    @GetMapping("/login/passwordWeb")
    public BaseResultModel passwordWeb(String username, String password) {
        DefaultResultModel defaultResultModel = new DefaultResultModel();
        defaultResultModel.setVal(loginService.passwordLogin(username, password, getWindowsCredentials()));
        return defaultResultModel;
    }


    @GetMapping("/login/passwordWeb2")
    public BaseResultModel passwordWeb2(String username, String password) {
        DefaultResultModel defaultResultModel = new DefaultResultModel();
//        defaultResultModel.setVal(loginService.passwordLogin(username, password, getWindowsCredentials()));
        defaultResultModel.setVal("11");
        return defaultResultModel;
    }
    @PostMapping("/login/emailWeb")
    public BaseResultModel emailWeb(String emailName, String emailCode) {
        DefaultResultModel defaultResultModel = new DefaultResultModel();
        defaultResultModel.setVal(loginService.emailLogin(emailName, emailCode, getWindowsCredentials()));
        return defaultResultModel;
    }

}
