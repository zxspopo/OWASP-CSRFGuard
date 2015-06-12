package org.owasp.csrfguard.redis;

import org.junit.Test;
import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.nostatus.redis.RedisCsrfGuard;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

/**
 * Created by Administrator on 2015/6/12.
 */
public class RedisCsrfGuardTest {

    @Test
    public void testLoad() {
        try {
            Properties properties = new Properties();
            properties.load(getClass().getClassLoader().getResourceAsStream("csrfguard.properties"));
            CsrfGuard guard = RedisCsrfGuard.getInstance();
            guard.load(properties);
            System.out.println(guard.toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }

    }
}
