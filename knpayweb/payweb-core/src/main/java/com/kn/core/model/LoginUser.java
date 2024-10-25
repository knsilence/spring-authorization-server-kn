package com.kn.core.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collection;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements Serializable {

    private String id;

    /**
     * 生日
     */
    private String birthday;


    /**
     * 1男2女3非男非女4时男时女  notNUll【默认为4】
     */
    private Integer gender;

    /**
     * 头像名称 notNUll
     */
    private String imgName;

    /**
     * 头像路径 notNUll
     */
    private String imgPath;

    /**
     * 账号名称 唯一的
     */
    private String loginname;

    /**
     * 昵称
     */
    private String nickname;

    /**
     *
     */
    private String memo;

    /**
     * 所在城市
     */
    private String country;

    /**
     *
     */
    private String createTime;

    private String updateTime;

//    /**
//     * 1匿名，2未匿名
//     */
//    @Column(name = "isanonymous")
//    private Integer isAnonymous;

    /**
     * 1未删除2已删除
     */
    private Integer delflag;

}
