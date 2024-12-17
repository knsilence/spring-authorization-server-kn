package com.kn.sendmsg.controller;

import com.kn.core.common.ApiStatus;
import com.kn.core.result.BaseResultModel;
import com.kn.core.result.DefaultResultModel;
import com.kn.sendmsg.common.SendMsgConstant;
import com.kn.sendmsg.utils.EmailUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@RestController
public class SendMsgController {
    @Autowired
    private EmailUtil emailUtil;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @GetMapping("/emailMsg/send")
    public DefaultResultModel sendEmailMsg(String emailName) {
        Random random = new Random();
        int randomNumber = 100000 + random.nextInt(900000);
        stringRedisTemplate.opsForValue().set(SendMsgConstant.REDIS_SENDMSG_EMAIL_PREX + "_" + emailName, String.valueOf(randomNumber), 300, TimeUnit.SECONDS);
        emailUtil.sendMail(emailName, "邮箱登陆验证码", String.valueOf(randomNumber));
        DefaultResultModel defaultResultModel = new DefaultResultModel();
        defaultResultModel.setCode(ApiStatus.CODE_200);
        return defaultResultModel;
    }

    @GetMapping("/emailMsg/valid")
    public Boolean validEmailMsg(String emailName, String emailCode) {
        String s = stringRedisTemplate.opsForValue().get(SendMsgConstant.REDIS_SENDMSG_EMAIL_PREX + "_" + emailName);
        if (s.equals(emailCode)) {
            return true;
        }
        return false;
    }
}
