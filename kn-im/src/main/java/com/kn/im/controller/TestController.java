package com.kn.im.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/login/user")
    public Object user(Authentication authentication) {
        return "spring:"+authentication.getName();

    }
}
