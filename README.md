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

**github地址：https://github.com/knsilence/spring-authorization-server-kn.git**

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
        <!--实现oauth授权认证-->
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

由于能够直接从github上看到代码，此处不全都展示代码

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

### 2.5 XXCodeGrantAuthenticationConverter

此文件为扩展登录方式-密码登录的转换文件，用于接收请求参数。

```

public class PasswordCodeGrantAuthenticationConverter implements AuthenticationConverter {

    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://baidu.com";

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!GrantTypes.GRANT_TYPE_PASSWORD_CODE.equals(grantType)) {
            return null;
        }
```

如果传入的GrantType不匹配当前Converter的GrantType，一定要return null，如果匹配，则会将参数转换为XXCodeGrantAuthenticationToken。

### 2.6 XXCodeGrantAuthenticationToken

此文件会寻找已经注册的XXCodeGrantAuthenticationProvider，并将参数传过去。想要注册让Token知道，需要在Provider中加上supports，否则Token找不到。

```
@Override
public boolean supports(Class<?> authentication) {
    return PasswordCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
}
```

### 2.7 XXCodeGrantAuthenticationProvider

此文件为验证用户信息，创建jwt token的重要部分！

在开头也需要匹配当前文件是否继承了Token并return null，因为授权中心会轮询已注册的自定义provider文件。

```
@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
PasswordCodeGrantAuthenticationToken authenticationToken=null;
try {
    authenticationToken =
            (PasswordCodeGrantAuthenticationToken) authentication;
} catch (Exception e) {
    return null;
}
```

如果匹配成功，需要查询当前账号是否正确，也就是是否能根据用户名查到用户信息。此处的userDetailService，需要在AuthorizationConfig配置文件中注入，然后传到当前provider文件。

```
UserInfoModel userInfoModel = null;
try {
    userInfoModel = (UserInfoModel) userDetailsService.loadUserByUsername(username);
} catch (UsernameNotFoundException e) {
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
}
```

而userDetailService文件可以继承

```
import org.springframework.security.core.userdetails.UserDetailsService;
```

继而重写方法

```
@Autowired
private UserMapper userMapper;
@Override
public UserDetails loadUserByUsername(String loginname) throws UsernameNotFoundException {
    UserInfo byLoginname = userMapper.findByLoginname(loginname);
    if(byLoginname==null)
        throw new BadCredentialsException("无此用户");
    List<GrantedAuthority> authlist=new ArrayList<GrantedAuthority>();
    UserInfoModel userInfoModel= new UserInfoModel(loginname, byLoginname.getPassword(), byLoginname.isDisabled(), byLoginname.isAccountExpired(), byLoginname.isCredentialsExpired(), byLoginname.isAccountLocked(), authlist);
    BeanUtils.copyProperties(byLoginname,userInfoModel);
    return userInfoModel;
}
```

同理在邮箱登录的Provider文件中，需要查找邮箱是否存在且邮箱验证码是否正确。

## 3、接口测试

密码登录

![image-20241217162514517](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241217162514517.png)

![image-20241217162448152](https://typora-pic-kn.oss-cn-qingdao.aliyuncs.com/img/image-20241217162448152.png)

## 4、更多的细节可参考github，代码有注释，有问题可直接评论，看到会回复。