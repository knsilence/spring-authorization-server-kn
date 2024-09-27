package com.kn.auth.pojo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import java.io.Serializable;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_info")
public class UserInfo implements Serializable {
    private static final long serialVersionUID = 1l;

    @Id
    @Column
    @GenericGenerator(name="systemUUID",strategy="uuid")
    @GeneratedValue(generator="systemUUID")
    private String id;

    /**
     * 生日
     */
    @Column
    private String birthday;

    @Column
    private String password;

    //1不可用2可用
    @Column(name = "isdisabled")
    private boolean isDisabled;

    //登录过期
    @Column(name = "isaccountexpired")
    private boolean isAccountExpired;

    //密码过期
    @Column(name = "iscredentialsexpired")
    private boolean isCredentialsExpired;

    //登录锁定
    @Column(name = "isaccountlocked")
    private boolean isAccountLocked;


    /**
     * 1男2女3非男非女4时男时女  notNUll【默认为4】
     */
    @Column
    private Integer gender;

    /**
     * 头像名称 notNUll
     */
    @Column(name = "imgname")
    private String imgName;

    /**
     * 头像路径 notNUll
     */
    @Column(name = "imgpath")
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
    @Column(name = "createtime")
    private String createTime;
    @Column(name = "updatetime")
    private String updateTime;

//    /**
//     * 1匿名，2未匿名
//     */
//    @Column(name = "isanonymous")
//    private Integer isAnonymous;

    /**
     * 1未删除2已删除
     */
    @Column(name = "delflag")
    private Integer delflag;

}
