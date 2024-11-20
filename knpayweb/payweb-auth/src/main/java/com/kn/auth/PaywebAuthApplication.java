package com.kn.auth;

import com.kn.core.config.MainInterface;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@MainInterface
@EnableDiscoveryClient
public class PaywebAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(PaywebAuthApplication.class, args);
    }

}
