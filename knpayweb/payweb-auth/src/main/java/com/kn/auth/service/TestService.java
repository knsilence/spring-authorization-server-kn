package com.kn.auth.service;

import com.kn.auth.pojo.UserInfo;

public interface TestService {
    UserInfo find(String loginname);
}
