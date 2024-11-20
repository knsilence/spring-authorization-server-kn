package com.kn.system;

import com.kn.core.config.MainInterface;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@MainInterface
@EnableDiscoveryClient
public class KnSystemApplication {

	public static void main(String[] args) {
		SpringApplication.run(KnSystemApplication.class, args);
	}

}
