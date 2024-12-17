package com.kn.core.common;

public class GrantTypes {

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
     * 自定义 grant type —— 密码 —— 短信验证码的key
     */
    public static final String OAUTH_PARAMETER_PASSWORD_PASSWORD = "password";
    /**
     * 自定义 grant type —— 邮箱登录—— 邮箱号
     */
    public static final String OAUTH_PARAMETER_EMAIL_NAME = "emailname";

    /**
     * 自定义 grant type —— 邮箱验证码 —— 邮箱验证码
     */
    public static final String OAUTH_PARAMETER_EMAIL_PASSWORD = "emailcode";
}
