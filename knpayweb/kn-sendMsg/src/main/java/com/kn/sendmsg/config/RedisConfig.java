package com.kn.sendmsg.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.Map;

@Configuration
public class RedisConfig {

    @Autowired
    private RedisConnectionFactory connectionFactory;

    @Bean
    public RedisTemplate<String, Object> initRedisTemplate() {
        // 创建RedisTemplate对象
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        // 设置连接工厂
        template.setConnectionFactory(connectionFactory);
        // 创建JSON序列化工具
        GenericJackson2JsonRedisSerializer jsonRedisSerializer =
                new GenericJackson2JsonRedisSerializer();
        // 设置Key的序列化
        template.setKeySerializer(RedisSerializer.string());
        template.setHashKeySerializer(RedisSerializer.string());
        // 设置Value的序列化
        template.setValueSerializer(jsonRedisSerializer);
        template.setHashValueSerializer(jsonRedisSerializer);
        // 返回
        return template;
    }

    @Bean
    public RedisTemplate<String, Map<String, Object>> mapRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Map<String, Object>> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);

        // 配置 Key 的序列化方式
        redisTemplate.setKeySerializer(new StringRedisSerializer());

        // 配置 Value 的序列化方式
        redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer());

        return redisTemplate;
    }

    //Redis Incr 命令将 key 中储存的数字值增一。
    //如果 key 不存在，那么 key 的值会先被初始化为 0 ，然后再执行 INCR 操作。
    //如果值包含错误的类型，或字符串类型的值不能表示为数字，那么返回一个错误。
    //本操作的值限制在 64 位(bit)有符号数字表示之内。

    /**
     * 递增
     *
     * @param key   键
     * @param delta 要增加几(大于0)
     * @return
     */
    public long incr(String key, long delta) {
        // 创建RedisTemplate对象
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        if (delta < 0) {
            throw new RuntimeException("递增因子必须大于0");
        }
        return template.opsForValue().increment(key, delta);
    }
    /* Redis Decr 命令将 key 中储存的数字值减一。
    如果 key 不存在，那么 key 的值会先被初始化为 0 ，然后再执行 DECR 操作。
    如果值包含错误的类型，或字符串类型的值不能表示为数字，那么返回一个错误。
    本操作的值限制在 64 位(bit)有符号数字表示之内。*/

    /**
     * 递减
     *
     * @param key   键
     * @param delta 要减少几(小于0)
     * @return
     */
    public long decr(String key, long delta) {
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        if (delta < 0) {
            throw new RuntimeException("递减因子必须大于0");
        }
        return template.opsForValue().increment(key, -delta);
    }

}
