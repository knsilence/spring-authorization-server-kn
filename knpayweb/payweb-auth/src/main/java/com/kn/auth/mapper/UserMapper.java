package com.kn.auth.mapper;

import com.kn.auth.pojo.UserInfo;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    public UserInfo findByLoginname(String loginname);
}
