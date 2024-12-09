package com.gzu.javawebproject;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.gzu.javawebproject.mapper")
public class JavawebprojectApplication {
    public static void main(String[] args) {
        SpringApplication.run(JavawebprojectApplication.class, args);
    }
}
