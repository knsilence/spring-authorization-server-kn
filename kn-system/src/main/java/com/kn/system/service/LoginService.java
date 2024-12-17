package com.kn.system.service;

import com.kn.core.common.TokenInfo;
import com.kn.core.result.BaseResultModel;

public interface LoginService {
    TokenInfo passwordLogin(String username,String password, String basicAuth);
    TokenInfo emailLogin(String emailName,String emailCode, String basicAuth);
}
