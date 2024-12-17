package com.kn.auth.client;

import com.kn.core.common.TokenInfo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "payweb-sendMsg")
public interface SendMsgClient {

    @GetMapping("/emailMsg/valid")
    public Boolean validEmailMsg(@RequestParam("emailName") String emailName,@RequestParam("emailCode") String emailCode);
}
