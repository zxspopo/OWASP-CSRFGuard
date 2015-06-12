package org.owasp.csrfguard;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.nostatus.redis.RedisClient;
import org.owasp.csrfguard.util.RandomGenerator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Map;

/**
 * Created by Administrator on 2015/6/11.
 */
public interface Guard {


    //销毁token信息
    void destoryStorage(String sessionId);


    String getSessionKey(String sesssionId);

    public void updateToken(HttpSession session);


    boolean isValidRequest(HttpServletRequest request, HttpServletResponse response);


    void rotateTokens(HttpServletRequest request);


    void verifySessionToken(HttpServletRequest request) throws CsrfGuardException;

    void verifyPageToken(HttpServletRequest request) throws CsrfGuardException;


    void verifyAjaxToken(HttpServletRequest request) throws CsrfGuardException;

    String getTokenValue(HttpServletRequest request, String uri);


    String getPageToken(HttpServletRequest request);

    Map<String, String> getAllPageToken(HttpServletRequest request);

    String getSessionToken(HttpServletRequest request);
}
