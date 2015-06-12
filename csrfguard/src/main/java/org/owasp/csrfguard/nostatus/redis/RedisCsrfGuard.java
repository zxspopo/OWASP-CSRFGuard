package org.owasp.csrfguard.nostatus.redis;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.util.RandomGenerator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;

/**
 * Created by Administrator on 2015/6/11.
 */
public class RedisCsrfGuard extends CsrfGuard {

    public RedisCsrfGuard() {
    }

    private static class SingletonHolder {
        public static final CsrfGuard instance = new RedisCsrfGuard();
    }

    public static CsrfGuard getInstance() {
        return SingletonHolder.instance;
    }


    @Override
    public String getTokenValue(HttpServletRequest request, String uri) {
        String tokenValue = null;
        HttpSession session = request.getSession(false);

        if (session != null) {
            String sessionId = session.getId();
            if (isTokenPerPageEnabled()) {

                String pageToken = RedisClient.getInstance().getHash(getPageTokenKey(sessionId), uri);

                if (pageToken == null) {
                    if (isTokenPerPagePrecreate()) {
                        pageToken = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
                        createPageToken(request.getSession().getId(), uri, pageToken);
                    }
                }
                tokenValue = pageToken;
            }

            if (tokenValue == null) {
                tokenValue = RedisClient.getInstance().get(getSessionKey(request.getSession().getId()));
            }
        }

        return tokenValue;
    }

    private void createPageToken(String sessionId, String uri, String tokenValue) {

        try {
            RedisClient.getInstance().setHash(getPageTokenKey(sessionId), uri, tokenValue);
        } catch (Exception e) {
            throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
        }
    }

    @Override
    public void updateToken(HttpSession session) {
        String tokenValue = RedisClient.getInstance().get(getSessionKey(session.getId()));

        /** Generate a new token and store it in the session. **/
        if (tokenValue == null) {
            try {
                tokenValue = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
            } catch (Exception e) {
                throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
            }

            RedisClient.getInstance().set(getSessionKey(session.getId()), tokenValue);
        }
    }


    @Override
    public boolean isValidRequest(HttpServletRequest request, HttpServletResponse response) {
        boolean valid = !isProtectedPageAndMethod(request);
        String tokenFromSession = RedisClient.getInstance().get(getSessionKey(request.getSession().getId()));

        /** sending request to protected resource - verify token **/
        if (tokenFromSession != null && !valid) {
            try {
                if (isAjaxEnabled() && isAjaxRequest(request)) {
                    verifyAjaxToken(request);
                } else if (isTokenPerPageEnabled()) {
                    verifyPageToken(request);
                } else {
                    verifySessionToken(request);
                }
                valid = true;
            } catch (CsrfGuardException csrfe) {
                for (IAction action : getActions()) {
                    try {
                        action.execute(request, response, csrfe, this);
                    } catch (CsrfGuardException exception) {
                        getLogger().log(LogLevel.Error, exception);
                    }
                }
            }

            /** rotate session and page tokens **/
            if (!isAjaxRequest(request) && isRotateEnabled()) {
                rotateTokens(request);
            }
            /** expected token in session - bad state **/
        } else if (tokenFromSession == null) {
            throw new IllegalStateException("CsrfGuard expects the token to exist in session at this point");
        } else {
            /** unprotected page - nothing to do **/
        }

        return valid;
    }


    public void rotateTokens(HttpServletRequest request) {
        /** rotate master token **/
        String tokenFromSession = null;

        try {
            tokenFromSession = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
        } catch (Exception e) {
            throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
        }

        String sessionId = request.getSession().getId();
        RedisClient.getInstance().set(getSessionKey(sessionId), tokenFromSession);

        /** rotate page token **/
        if (isTokenPerPageEnabled()) {
            try {
                RedisClient.getInstance().setHash(getPageTokenKey(sessionId), request.getRequestURI(), RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
            } catch (Exception e) {
                throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
            }
        }
    }


    public void verifySessionToken(HttpServletRequest request) throws CsrfGuardException {
        String tokenFromSession = RedisClient.getInstance().get(getSessionKey());
        String tokenFromRequest = request.getParameter(getTokenName());

        if (tokenFromRequest == null) {
            /** FAIL: token is missing from the request **/
            throw new CsrfGuardException("required token is missing from the request");
        } else if (!tokenFromSession.equals(tokenFromRequest)) {
            /** FAIL: the request token does not match the session token **/
            throw new CsrfGuardException("request token does not match session token");
        }
    }

    public void verifyPageToken(HttpServletRequest request) throws CsrfGuardException {

        String sessionId = request.getSession().getId();
        String pageToken = RedisClient.getInstance().getHash(getPageTokenKey(sessionId), request.getRequestURI());

        String tokenFromPages = pageToken != null ? pageToken : null;
        String tokenFromSession = RedisClient.getInstance().get(getSessionKey(sessionId));
        String tokenFromRequest = request.getParameter(getTokenName());

        if (tokenFromRequest == null) {
            /** FAIL: token is missing from the request **/
            throw new CsrfGuardException("required token is missing from the request");
        } else if (tokenFromPages != null) {
            if (!tokenFromPages.equals(tokenFromRequest)) {
                /** FAIL: request does not match page token **/
                throw new CsrfGuardException("request token does not match page token");
            }
        } else if (!tokenFromSession.equals(tokenFromRequest)) {
            /** FAIL: the request token does not match the session token **/
            throw new CsrfGuardException("request token does not match session token");
        }
    }


    public void verifyAjaxToken(HttpServletRequest request) throws CsrfGuardException {
        String tokenFromSession = RedisClient.getInstance().get(getSessionKey(request.getSession().getId()));
        String tokenFromRequest = request.getHeader(getTokenName());

        if (tokenFromRequest == null) {
            /** FAIL: token is missing from the request **/
            throw new CsrfGuardException("required token is missing from the request");
        } else if (!tokenFromSession.equals(tokenFromRequest)) {
            /** FAIL: the request token does not match the session token **/
            throw new CsrfGuardException("request token does not match session token");
        }
    }

    public String getSessionKey(String sessionId) {
        return sessionId + super.getSessionKey();
    }

    @Override
    public void destoryStorage(String sessionId) {
        RedisClient.getInstance().delete(getSessionKey(sessionId));
        RedisClient.getInstance().delete(getPageTokenKey(sessionId));
    }

    public String getPageTokenKey(String sessionId) {
        return sessionId + PAGE_TOKENS_KEY;
    }

    @Override
    public String getPageToken(HttpServletRequest request) {
        String sessionId = request.getSession(true).getId();
        return RedisClient.getInstance().getHash(getPageTokenKey(sessionId), request.getRequestURI());
    }

    @Override
    public Map<String, String> getAllPageToken(HttpServletRequest request) {
        String sessionId = request.getSession(true).getId();
        return RedisClient.getInstance().getHash(getPageTokenKey(sessionId));
    }

    @Override
    public String getSessionToken(HttpServletRequest request) {
        String sessionId = request.getSession(true).getId();
        return RedisClient.getInstance().get(getSessionKey(sessionId));
    }
}
