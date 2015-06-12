package org.owasp.csrfguard.nostatus.redis;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.util.Map;
import java.util.Properties;

/**
 * Created by Administrator on 2015/6/11.
 */
public class RedisClient {

    private static RedisClient instance;

    private Jedis jedis;//非切片额客户端连接
    private JedisPool jedisPool;//非切片连接池

    private RedisClient() {
    }

    public static RedisClient getInstance() {
        if (instance == null) {
            synchronized (RedisClient.class) {
                if (instance == null) {
                    instance = new RedisClient();
                }
            }
        }
        return instance;
    }

    /**
     * 在ContextListener中初始化，之后不要在加载配置!!!
     * <p/>
     * 初始化非切片池
     */
    public void initialPool(Properties properties) {

        if (jedisPool == null) {
            synchronized (RedisClient.class) {
                if (jedisPool == null) {

                    // 池基本配置
                    JedisPoolConfig config = new JedisPoolConfig();

                    config.setMaxTotal(Integer.valueOf(properties.getProperty("redis.pool.maxActive", "100")));
                    config.setMaxIdle(Integer.valueOf(properties
                            .getProperty("redis.pool.maxIdle", "20")));
                    config.setMaxWaitMillis(Long.valueOf(properties.getProperty("redis.pool.maxWait", "1000")));
                    config.setTestOnBorrow(Boolean.valueOf(properties.getProperty("redis.pool.testOnBorrow", "true")));
                    config.setTestOnReturn(Boolean.valueOf(properties.getProperty("redis.pool.testOnReturn", "true")));
                    jedisPool = new JedisPool(config, properties.getProperty("redis.ip"),
                            Integer.valueOf(properties.getProperty("redis.port")), 2000, "".equals(properties.getProperty("redis.password")) ? null : properties.getProperty("redis.password"));
                }
            }
        }
    }

    public void set(String key, String value) {
        jedis = jedisPool.getResource();
        jedis.set(key, value);
        jedisPool.returnResource(jedis);
    }

    public <T> T get(String key) {

        jedis = jedisPool.getResource();
        T t = (T) jedis.get(key);
        jedisPool.returnResource(jedis);
        return t;
    }

    public void delete(String key) {
        jedis = jedisPool.getResource();
        jedis.del(key);
        jedisPool.returnResource(jedis);
    }

    public void setHash(String key, Map<String, String> map) {
        jedis = jedisPool.getResource();
        if (map != null && !map.isEmpty()) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                jedis.hset(key, entry.getKey(), entry.getValue());
            }
        }
        jedisPool.returnResource(jedis);
    }

    public void setHash(String key, String field, String value) {
        jedis = jedisPool.getResource();
        jedis.hset(key, field, value);

        jedisPool.returnResource(jedis);
    }


    public void delHash(String key, String... fileds) {

        jedis = jedisPool.getResource();
        jedis.hdel(key, fileds);
        jedisPool.returnResource(jedis);
    }

    public String getHash(String key, String field) {

        jedis = jedisPool.getResource();
        String result = jedis.hget(key, field);
        jedisPool.returnResource(jedis);
        return result;
    }

    public Map<String, String> getHash(String key) {
        jedis = jedisPool.getResource();
        Map<String, String> result = jedis.hgetAll(key);
        jedisPool.returnResource(jedis);
        return result;

    }


}
