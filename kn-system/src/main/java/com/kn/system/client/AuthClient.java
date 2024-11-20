package com.kn.system.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
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
}
