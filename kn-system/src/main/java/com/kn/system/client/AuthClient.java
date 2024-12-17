package com.kn.system.client;

import com.kn.core.common.TokenInfo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

/*https://blog.itpub.net/70015773/viewspace-3030998/*/
@FeignClient(name = "payweb-authserver")
public interface AuthClient {

    /**
     * 下载日志添加接口
     *
     * @param
     * @return
     */
    @GetMapping("/test")
    public String test();


    /**
     * 账号密码登录
     */
    @RequestMapping(method = RequestMethod.POST, value = "/oauth2/token")
    public TokenInfo webPassword(
            @RequestParam("grant_type") String grant_type,
            @RequestParam("scope") String scope,
            @RequestParam("loginname") String username,
            @RequestParam("password") String password,
            @RequestHeader("Authorization") String authorization);
    /**
     * 邮箱登录
     */
    @RequestMapping(method = RequestMethod.POST, value = "/oauth2/token")
    public TokenInfo webEmail(
            @RequestParam("grant_type") String grant_type,
            @RequestParam("scope") String scope,
            @RequestParam("emailname") String username,
            @RequestParam("emailcode") String password,
            @RequestHeader("Authorization") String authorization);

}
