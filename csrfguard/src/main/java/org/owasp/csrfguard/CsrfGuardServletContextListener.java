package org.owasp.csrfguard;

import java.io.IOException;
import java.io.InputStream;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.owasp.csrfguard.constant.StorageTypeConstant;
import org.owasp.csrfguard.nostatus.redis.RedisClient;
import org.owasp.csrfguard.nostatus.redis.RedisCsrfGuard;
import org.owasp.csrfguard.util.Resources;

import org.owasp.csrfguard.util.Streams;

public class CsrfGuardServletContextListener implements ServletContextListener {

    private final static String CONFIG_PARAM = "Owasp.CsrfGuard.Config";

    private final static String CONFIG_PRINT_PARAM = "Owasp.CsrfGuard.Config.Print";

    private final static String CONFIG_CSRFGRARD_TYPE = "Owasp.CsrfGuard.Type";

    @Override
    public void contextInitialized(ServletContextEvent event) {
        ServletContext context = event.getServletContext();
        String config = context.getInitParameter(CONFIG_PARAM);
        String storageType = context.getInitParameter(CONFIG_CSRFGRARD_TYPE);

        if (config == null) {
            throw new RuntimeException(String.format("failure to specify context init-param - %s", CONFIG_PARAM));
        }

        InputStream is = null;
        Properties properties = new Properties();

        try {
            is = Resources.getResourceStream(config, context, CsrfGuardServletContextListener.class);
            properties.load(is);
            CsrfGuardFactory.setCsrfGuard(storageType, properties);
            RedisClient client = RedisClient.getInstance();
            client.initialPool(properties);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            Streams.close(is);
        }

        String printConfig = context.getInitParameter(CONFIG_PRINT_PARAM);

        if (printConfig != null && Boolean.parseBoolean(printConfig)) {
            context.log(CsrfGuardFactory.getCsrfGuard().toString());
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
        /** nothing to do **/
    }

}
