package com.kn.sendmsg.utils;

import com.baomidou.mybatisplus.core.toolkit.StringUtils;
import io.netty.util.internal.StringUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

@Component
public class EmailUtil {
    @Value("${spring.mail.username}")
    private String from;
    @Autowired
    private JavaMailSender sender;

    public boolean sendMail(String to,String subject, String body){
        if (StringUtils.isBlank(to)){
            return false;
        }
        //构建标准的简单邮件信息
        //发送人和xml保持一致
        SimpleMailMessage m=new SimpleMailMessage();
        //发送人
        m.setFrom(from);
        //接收人
        m.setTo(to);
        //邮件标题
        m.setSubject(subject);
        //内容
        m.setText(body);
        sender.send(m);//发送邮件
        System.out.println("发送成功！");
        return true;
    }

}