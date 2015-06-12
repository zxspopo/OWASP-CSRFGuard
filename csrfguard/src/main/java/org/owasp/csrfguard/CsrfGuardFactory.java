package org.owasp.csrfguard;

import org.owasp.csrfguard.constant.StorageTypeConstant;
import org.owasp.csrfguard.nostatus.redis.RedisCsrfGuard;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

/**
 * Created by Administrator on 2015/6/11.
 */
public final class CsrfGuardFactory {

    private static CsrfGuard csrfGuard;

    public static CsrfGuard getCsrfGuard() {
        return csrfGuard;
    }

    /**
     * 根据CsrfGuard的类型选择不同的方式存放sessionKey，此处加载配置文件
     *
     * @param properties
     * @param storageType
     */
    public static void setCsrfGuard(String storageType, Properties properties) throws IllegalAccessException, NoSuchAlgorithmException, InstantiationException, IOException, NoSuchProviderException, ClassNotFoundException {

        if (StorageTypeConstant.SESSION.equals(storageType)) {
            csrfGuard = CsrfGuard.getInstance();
            csrfGuard.load(properties);
        } else if (StorageTypeConstant.REDIS.equals(storageType)) {
           csrfGuard = RedisCsrfGuard.getInstance();
            csrfGuard.load(properties);
        } else {
            CsrfGuardFactory.csrfGuard = CsrfGuard.getInstance();
            csrfGuard.load(properties);
        }
    }

}
