package com.kn.auth.service.impl;

import com.kn.auth.mapper.UserMapper;
import com.kn.auth.pojo.UserInfo;
import com.kn.auth.service.TestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class TestServiceImpl implements TestService {


    @Autowired
    private UserMapper userMapper;

    @Override
    public UserInfo find(String loginname) {
        UserInfo byLoginname = userMapper.findByLoginname(loginname);
        return byLoginname;
    }
}
