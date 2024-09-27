package com.kn.auth.service.impl;

import com.kn.auth.mapper.UserMapper;
import com.kn.auth.model.UserInfoModel;
import com.kn.auth.pojo.UserInfo;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service("UserDetailsService")
@Transactional
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String loginname) throws UsernameNotFoundException {
        UserInfo byLoginname = userMapper.findByLoginname(loginname);
        List<GrantedAuthority> authlist=new ArrayList<GrantedAuthority>();
        UserInfoModel userInfoModel= new UserInfoModel(loginname, byLoginname.getPassword(), byLoginname.isDisabled(), byLoginname.isAccountExpired(), byLoginname.isCredentialsExpired(), byLoginname.isAccountLocked(), authlist);
        BeanUtils.copyProperties(byLoginname,userInfoModel);
        return userInfoModel;
    }
}
