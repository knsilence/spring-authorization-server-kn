package com.kn.auth.controller;

import com.kn.auth.service.TestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @Autowired
    private TestService testService;

    @GetMapping("/test")
    public String test() {
        return "dd";
    }
}
