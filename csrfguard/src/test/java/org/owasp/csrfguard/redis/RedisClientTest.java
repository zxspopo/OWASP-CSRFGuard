package org.owasp.csrfguard.redis;

import org.junit.Assert;
import org.junit.Test;
import org.owasp.csrfguard.nostatus.redis.RedisClient;

/**
 * Created by Administrator on 2015/6/11.
 */
public class RedisClientTest {


    @Test
    public void testRedis() {
        RedisClient client = RedisClient.getInstance();
        client.set("key1", "value1");
        Assert.assertEquals("value1", client.get("key1"));
        client.delete("key1");
        Assert.assertNull(client.get("key1"));

    }
}
