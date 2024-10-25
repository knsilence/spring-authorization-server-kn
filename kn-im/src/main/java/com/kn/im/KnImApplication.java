package com.kn.im;

import com.kn.core.config.MainInterface;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@MainInterface
public class KnImApplication {

	public static void main(String[] args) {
		SpringApplication.run(KnImApplication.class, args);
	}

}
