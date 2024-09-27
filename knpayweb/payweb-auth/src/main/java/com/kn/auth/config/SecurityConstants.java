package com.kn.auth.config;


/**
 * security 常量类
 *
 */
public class SecurityConstants {

    /**
     * 登录方式——短信验证码
     */
    public static final String SMS_LOGIN_TYPE = "sms";

    /**
     * 登录方式——账号密码登录
     */
    public static final String PASSWORD_LOGIN_TYPE = "password";

    /**
     * 权限在token中的key
     */
    public static final String AUTHORITIES_KEY = "authorities";

    /**
     * 自定义 grant type —— 短信验证码
     */
    public static final String GRANT_TYPE_EMAIL_CODE = "email_code";
    /**
     * 自定义 grant type —— 密码登录
     */
    public static final String GRANT_TYPE_PASSWORD_CODE = "password_code";

    /**
     * 自定义 grant type —— 密码登录—— 账号
     */
    public static final String OAUTH_PARAMETER_PASSWORD_NAME = "loginname";

    /**
     * 自定义 grant type —— 短信验证码 —— 短信验证码的key
     */
    public static final String OAUTH_PARAMETER_PASSWORD_PASSWORD = "password";

}
