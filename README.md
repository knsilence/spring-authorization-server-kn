# spring authorization server实现oauth2.1密码、邮箱登录

## 1、技术栈

> Springboot3
>
> Java21
>
> Spring authorization server
>
> Redis
>
> Mysql

## 2、实现过程

### 2.1 搭建spring架构

首先搭建kn-parent和kn-core两个项目，作为以后的依赖父包。

![image-20241217145933450](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241217145933450.png)

![image-20241217150012607](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241217150012607.png)

### 2.2 pom文件

里面的kn-parent和kn-core即为2.1中搭建的父包

```
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <groupId>com.kn</groupId>
        <artifactId>kn-parent</artifactId>
        <version>0.0.1-SNAPSHOT</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.kn</groupId>
    <artifactId>kn-auth</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>kn-auth</name>
    <dependencies>
        <dependency>
            <groupId>com.kn</groupId>
            <artifactId>kn-core</artifactId>
            <version>0.0.1-SNAPSHOT</version>
        </dependency>
        <!--实现oauth授权-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-authorization-server</artifactId>
        </dependency>
    </dependencies>

    <build>
        <finalName>${project.artifactId}</finalName>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <executions>
                    <execution>
                        <goals>
                            <goal>repackage</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>

</project>

```

### 2.3 授权认证项目kn-auth所有文件集

由于能欧直接

![image-20241217150445870](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241217150445870.png)

### 2.4 SendMsgClient

此文件为验证邮箱验证码是否准确的接口，使用了openfeign和nacos，外部调用另一个项目的接口，在EmailCodeGrantAuthenticationProvider中验证邮箱code时使用。

```
@FeignClient(name = "payweb-sendMsg")
public interface SendMsgClient {

    @GetMapping("/emailMsg/valid")
    public Boolean validEmailMsg(@RequestParam("emailName") String emailName,@RequestParam("emailCode") String emailCode);
}
```

2.5 AuthorizationConfig