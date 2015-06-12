/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011
 * All rights reserved.
 * <p/>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * <p/>
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of OWASP nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 * <p/>
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard;

import org.owasp.csrfguard.action.IAction;
import org.owasp.csrfguard.log.ILogger;
import org.owasp.csrfguard.log.LogLevel;
import org.owasp.csrfguard.util.RandomGenerator;
import org.owasp.csrfguard.util.Streams;
import org.owasp.csrfguard.util.Writers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.*;

public class CsrfGuard implements Guard {

    public final static String PAGE_TOKENS_KEY = "Owasp_CsrfGuard_Pages_Tokens_Key";

    protected final static String ACTION_PREFIX = "org.owasp.csrfguard.action.";

    protected final static String PROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.protected.";

    protected final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";

    protected ILogger logger = null;

    protected String tokenName = null;

    protected int tokenLength = -1;

    protected boolean rotate = false;

    protected boolean tokenPerPage = false;

    protected boolean tokenPerPagePrecreate;

    protected SecureRandom prng = null;

    protected String newTokenLandingPage = null;

    protected boolean useNewTokenLandingPage = false;

    protected boolean ajax = false;

    protected boolean protect = false;

    protected String sessionKey = null;

    protected Set<String> protectedPages = null;

    protected Set<String> unprotectedPages = null;

    protected Set<String> protectedMethods = null;

    protected List<IAction> actions = null;

    @Override
    public void destoryStorage(String sessionId) {

    }

    @Override
    public String getSessionKey(String sesssionId) {
        return getSessionKey();
    }


    private static class SingletonHolder {
        public static final CsrfGuard instance = new CsrfGuard();
    }

    public static CsrfGuard getInstance() {
        return SingletonHolder.instance;
    }

    public void load(Properties properties) throws NoSuchAlgorithmException, InstantiationException, IllegalAccessException, ClassNotFoundException, IOException, NoSuchProviderException {

        /** load simple properties **/
        this.setLogger((ILogger) Class.forName(properties.getProperty("org.owasp.csrfguard.Logger", "org.owasp.csrfguard.log.ConsoleLogger")).newInstance());
        this.setTokenName(properties.getProperty("org.owasp.csrfguard.TokenName", "OWASP_CSRFGUARD"));
        this.setTokenLength(Integer.parseInt(properties.getProperty("org.owasp.csrfguard.TokenLength", "32")));
        this.setRotate(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Rotate", "false")));
        this.setTokenPerPage(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.TokenPerPage", "false")));
        this.setTokenPerPagePrecreate(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.TokenPerPagePrecreate", "false")));
        this.setPrng(SecureRandom.getInstance(properties.getProperty("org.owasp.csrfguard.PRNG", "SHA1PRNG"), properties.getProperty("org.owasp.csrfguard.PRNG.Provider", "SUN")));
        this.setNewTokenLandingPage(properties.getProperty("org.owasp.csrfguard.NewTokenLandingPage"));

        //default to false if newTokenLandingPage is not set; default to true if set.
        if (this.getNewTokenLandingPage() == null) {
            this.setUseNewTokenLandingPage(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.UseNewTokenLandingPage", "false")));
        } else {
            this.setUseNewTokenLandingPage(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.UseNewTokenLandingPage", "true")));
        }
        this.setSessionKey(properties.getProperty("org.owasp.csrfguard.SessionKey", "OWASP_CSRFGUARD_KEY"));
        this.setAjax(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Ajax", "false")));
        this.setProtect(Boolean.valueOf(properties.getProperty("org.owasp.csrfguard.Protect", "false")));

        /** first pass: instantiate actions **/
        Map<String, IAction> actionsMap = new HashMap<String, IAction>();

        for (Object obj : properties.keySet()) {
            String key = (String) obj;

            if (key.startsWith(ACTION_PREFIX)) {
                String directive = key.substring(ACTION_PREFIX.length());
                int index = directive.indexOf('.');

                /** action name/class **/
                if (index < 0) {
                    String actionClass = properties.getProperty(key);
                    IAction action = (IAction) Class.forName(actionClass).newInstance();

                    action.setName(directive);
                    actionsMap.put(action.getName(), action);
                    this.getActions().add(action);
                }
            }
        }

        /** second pass: initialize action parameters **/
        for (Object obj : properties.keySet()) {
            String key = (String) obj;

            if (key.startsWith(ACTION_PREFIX)) {
                String directive = key.substring(ACTION_PREFIX.length());
                int index = directive.indexOf('.');

                /** action name/class **/
                if (index >= 0) {
                    String actionName = directive.substring(0, index);
                    IAction action = actionsMap.get(actionName);

                    if (action == null) {
                        throw new IOException(String.format("action class %s has not yet been specified", actionName));
                    }

                    String parameterName = directive.substring(index + 1);
                    String parameterValue = properties.getProperty(key);

                    action.setParameter(parameterName, parameterValue);
                }
            }
        }

        /** ensure at least one action was defined **/
        if (this.getActions().size() <= 0) {
            throw new IOException("failure to define at least one action");
        }

        /** initialize protected, unprotected pages **/
        for (Object obj : properties.keySet()) {
            String key = (String) obj;

            if (key.startsWith(PROTECTED_PAGE_PREFIX)) {
                String directive = key.substring(PROTECTED_PAGE_PREFIX.length());
                int index = directive.indexOf('.');

                /** page name/class **/
                if (index < 0) {
                    String pageUri = properties.getProperty(key);

                    this.getProtectedPages().add(pageUri);
                }
            }

            if (key.startsWith(UNPROTECTED_PAGE_PREFIX)) {
                String directive = key.substring(UNPROTECTED_PAGE_PREFIX.length());
                int index = directive.indexOf('.');

                /** page name/class **/
                if (index < 0) {
                    String pageUri = properties.getProperty(key);

                    this.getUnprotectedPages().add(pageUri);
                }
            }
        }

        /** initialize protected methods **/
        String methodList = properties.getProperty("org.owasp.csrfguard.ProtectedMethods");
        if (methodList != null && methodList.trim().length() != 0) {
            for (String method : methodList.split(",")) {
                this.getProtectedMethods().add(method.trim());
            }
        }
    }

    public CsrfGuard() {
        actions = new ArrayList<IAction>();
        protectedPages = new HashSet<String>();
        unprotectedPages = new HashSet<String>();
        protectedMethods = new HashSet<String>();
    }

    public ILogger getLogger() {
        return logger;
    }

    private void setLogger(ILogger logger) {
        this.logger = logger;
    }

    public String getTokenName() {
        return tokenName;
    }

    private void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    public int getTokenLength() {
        return tokenLength;
    }

    private void setTokenLength(int tokenLength) {
        this.tokenLength = tokenLength;
    }

    public boolean isRotateEnabled() {
        return rotate;
    }

    private void setRotate(boolean rotate) {
        this.rotate = rotate;
    }

    public boolean isTokenPerPageEnabled() {
        return tokenPerPage;
    }

    private void setTokenPerPage(boolean tokenPerPage) {
        this.tokenPerPage = tokenPerPage;
    }

    public boolean isTokenPerPagePrecreate() {
        return tokenPerPagePrecreate;
    }

    private void setTokenPerPagePrecreate(boolean tokenPerPagePrecreate) {
        this.tokenPerPagePrecreate = tokenPerPagePrecreate;
    }

    public SecureRandom getPrng() {
        return prng;
    }

    private void setPrng(SecureRandom prng) {
        this.prng = prng;
    }

    public String getNewTokenLandingPage() {
        return newTokenLandingPage;
    }

    private void setNewTokenLandingPage(String newTokenLandingPage) {
        this.newTokenLandingPage = newTokenLandingPage;
    }

    public boolean isUseNewTokenLandingPage() {
        return useNewTokenLandingPage;
    }

    private void setUseNewTokenLandingPage(boolean useNewTokenLandingPage) {
        this.useNewTokenLandingPage = useNewTokenLandingPage;
    }

    public boolean isAjaxEnabled() {
        return ajax;
    }

    private void setAjax(boolean ajax) {
        this.ajax = ajax;
    }

    public boolean isProtectEnabled() {
        return protect;
    }

    public void setProtect(boolean protect) {
        this.protect = protect;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    private void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    public Set<String> getProtectedPages() {
        return protectedPages;
    }

    public Set<String> getUnprotectedPages() {
        return unprotectedPages;
    }

    public Set<String> getProtectedMethods() {
        return protectedMethods;
    }


    public List<IAction> getActions() {
        return actions;
    }

    public String getTokenValue(HttpServletRequest request) {
        return getTokenValue(request, request.getRequestURI());
    }

    public String getTokenValue(HttpServletRequest request, String uri) {
        String tokenValue = null;
        HttpSession session = request.getSession(false);

        if (session != null) {
            if (isTokenPerPageEnabled()) {
                @SuppressWarnings("unchecked")
                Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

                if (pageTokens != null) {
                    if (isTokenPerPagePrecreate()) {
                        createPageToken(pageTokens, uri);
                    }
                    tokenValue = pageTokens.get(uri);

                }
            }

            if (tokenValue == null) {
                tokenValue = (String) session.getAttribute(getSessionKey());
            }
        }

        return tokenValue;
    }

    @Override
    public String getPageToken(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

        return (pageTokens != null ? pageTokens.get(request.getRequestURI()) : null);
    }

    @Override
    public Map<String, String> getAllPageToken(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);
        return pageTokens;
    }

    @Override
    public String getSessionToken(HttpServletRequest request) {
        HttpSession session = request.getSession(true);
        String tokenFromSession = (String) session.getAttribute(getSessionKey(session.getId()));
        return tokenFromSession;
    }

    public boolean isValidRequest(HttpServletRequest request, HttpServletResponse response) {
        boolean valid = !isProtectedPageAndMethod(request);
        HttpSession session = request.getSession(true);
        String tokenFromSession = (String) session.getAttribute(getSessionKey());

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

    public void updateToken(HttpSession session) {
        String tokenValue = (String) session.getAttribute(getSessionKey());

        /** Generate a new token and store it in the session. **/
        if (tokenValue == null) {
            try {
                tokenValue = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
            } catch (Exception e) {
                throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
            }

            session.setAttribute(getSessionKey(), tokenValue);
        }
    }

    public void updateTokens(HttpServletRequest request) {
        /** cannot create sessions if response already committed **/
        HttpSession session = request.getSession(false);

        if (session != null) {
            /** create master token if it does not exist **/
            updateToken(session);

            /** create page specific token **/
            if (isTokenPerPageEnabled()) {
                @SuppressWarnings("unchecked")
                Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

                /** first time initialization **/
                if (pageTokens == null) {
                    pageTokens = new HashMap<String, String>();
                    session.setAttribute(CsrfGuard.PAGE_TOKENS_KEY, pageTokens);
                }

                /** create token if it does not exist **/
                if (isProtectedPageAndMethod(request)) {
                    createPageToken(pageTokens, request.getRequestURI());
                }
            }
        }
    }

    /**
     * Create page token if it doesn't exist.
     *
     * @param pageTokens A map of tokens. If token doesn't exist it will be added.
     * @param uri        The key for the tokens.
     */
    private void createPageToken(Map<String, String> pageTokens, String uri) {

        if (pageTokens == null)
            return;

        /** create token if it does not exist **/
        if (pageTokens.containsKey(uri))
            return;
        try {
            pageTokens.put(uri, RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
        } catch (Exception e) {
            throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
        }
    }

    public void writeLandingPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String landingPage = getNewTokenLandingPage();

        /** default to current page **/
        if (landingPage == null) {
            StringBuilder sb = new StringBuilder();

            sb.append(request.getContextPath());
            sb.append(request.getServletPath());

            landingPage = sb.toString();
        }

        /** create auto posting form **/
        StringBuilder sb = new StringBuilder();

        sb.append("<html>\r\n");
        sb.append("<head>\r\n");
        sb.append("<title>OWASP CSRFGuard Project - New Token Landing Page</title>\r\n");
        sb.append("</head>\r\n");
        sb.append("<body>\r\n");
        sb.append("<script type=\"text/javascript\">\r\n");
        sb.append("var form = document.createElement(\"form\");\r\n");
        sb.append("form.setAttribute(\"method\", \"post\");\r\n");
        sb.append("form.setAttribute(\"action\", \"");
        sb.append(landingPage);
        sb.append("\");\r\n");

        /** only include token if needed **/
        if (isProtectedPage(landingPage)) {
            sb.append("var hiddenField = document.createElement(\"input\");\r\n");
            sb.append("hiddenField.setAttribute(\"type\", \"hidden\");\r\n");
            sb.append("hiddenField.setAttribute(\"name\", \"");
            sb.append(getTokenName());
            sb.append("\");\r\n");
            sb.append("hiddenField.setAttribute(\"value\", \"");
            sb.append(getTokenValue(request, landingPage));
            sb.append("\");\r\n");
            sb.append("form.appendChild(hiddenField);\r\n");
        }

        sb.append("document.body.appendChild(form);\r\n");
        sb.append("form.submit();\r\n");
        sb.append("</script>\r\n");
        sb.append("</body>\r\n");
        sb.append("</html>\r\n");

        String code = sb.toString();

        /** setup headers **/
        response.setContentType("text/html");
        response.setContentLength(code.length());

        /** write auto posting form **/
        OutputStream output = null;
        PrintWriter writer = null;

        try {
            output = response.getOutputStream();
            writer = new PrintWriter(output);

            writer.write(code);
            writer.flush();
        } finally {
            Writers.close(writer);
            Streams.close(output);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("\r\n*****************************************************\r\n");
        sb.append("*Guard Type is ").append(this.getClass().getName()).append(" \r\n");
        sb.append("* Owasp.CsrfGuard Properties\r\n");
        sb.append("*\r\n");
        sb.append(String.format("* Logger: %s\r\n", getLogger().getClass().getName()));
        sb.append(String.format("* NewTokenLandingPage: %s\r\n", getNewTokenLandingPage()));
        sb.append(String.format("* PRNG: %s\r\n", getPrng().getAlgorithm()));
        sb.append(String.format("* SessionKey: %s\r\n", getSessionKey()));
        sb.append(String.format("* TokenLength: %s\r\n", getTokenLength()));
        sb.append(String.format("* TokenName: %s\r\n", getTokenName()));
        sb.append(String.format("* Ajax: %s\r\n", isAjaxEnabled()));
        sb.append(String.format("* Rotate: %s\r\n", isRotateEnabled()));
        sb.append(String.format("* TokenPerPage: %s\r\n", isTokenPerPageEnabled()));

        for (IAction action : actions) {
            sb.append(String.format("* Action: %s\r\n", action.getClass().getName()));

            for (String name : action.getParameterMap().keySet()) {
                String value = action.getParameter(name);

                sb.append(String.format("*\tParameter: %s = %s\r\n", name, value));
            }
        }
        sb.append("*****************************************************\r\n");

        return sb.toString();
    }

    protected boolean isAjaxRequest(HttpServletRequest request) {
        return request.getHeader("X-Requested-With") != null;
    }

    public void verifyAjaxToken(HttpServletRequest request) throws CsrfGuardException {
        HttpSession session = request.getSession(true);
        String tokenFromSession = (String) session.getAttribute(getSessionKey());
        String tokenFromRequest = request.getHeader(getTokenName());

        if (tokenFromRequest == null) {
            /** FAIL: token is missing from the request **/
            throw new CsrfGuardException("required token is missing from the request");
        } else if (!tokenFromSession.equals(tokenFromRequest)) {
            /** FAIL: the request token does not match the session token **/
            throw new CsrfGuardException("request token does not match session token");
        }
    }

    public void verifyPageToken(HttpServletRequest request) throws CsrfGuardException {
        HttpSession session = request.getSession(true);
        @SuppressWarnings("unchecked")
        Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

        String tokenFromPages = (pageTokens != null ? pageTokens.get(request.getRequestURI()) : null);
        String tokenFromSession = (String) session.getAttribute(getSessionKey());
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

    public void verifySessionToken(HttpServletRequest request) throws CsrfGuardException {
        HttpSession session = request.getSession(true);
        String tokenFromSession = (String) session.getAttribute(getSessionKey());
        String tokenFromRequest = request.getParameter(getTokenName());

        if (tokenFromRequest == null) {
            /** FAIL: token is missing from the request **/
            throw new CsrfGuardException("required token is missing from the request");
        } else if (!tokenFromSession.equals(tokenFromRequest)) {
            /** FAIL: the request token does not match the session token **/
            throw new CsrfGuardException("request token does not match session token");
        }
    }

    public void rotateTokens(HttpServletRequest request) {
        HttpSession session = request.getSession(true);

        /** rotate master token **/
        String tokenFromSession = null;

        try {
            tokenFromSession = RandomGenerator.generateRandomId(getPrng(), getTokenLength());
        } catch (Exception e) {
            throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
        }

        session.setAttribute(getSessionKey(), tokenFromSession);

        /** rotate page token **/
        if (isTokenPerPageEnabled()) {
            @SuppressWarnings("unchecked")
            Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);

            try {
                pageTokens.put(request.getRequestURI(), RandomGenerator.generateRandomId(getPrng(), getTokenLength()));
            } catch (Exception e) {
                throw new RuntimeException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
            }
        }
    }

    public boolean isProtectedPage(String uri) {
        boolean retval = !isProtectEnabled();

        for (String protectedPage : protectedPages) {
            if (isUriExactMatch(protectedPage, uri)) {
                return true;
            } else if (isUriMatch(protectedPage, uri)) {
                retval = true;
            }
        }

        for (String unprotectedPage : unprotectedPages) {
            if (isUriExactMatch(unprotectedPage, uri)) {
                return false;
            } else if (isUriMatch(unprotectedPage, uri)) {
                retval = false;
            }
        }

        return retval;
    }

    public boolean isProtectedMethod(String method) {
        boolean retval = false;

        if (protectedMethods.isEmpty() || protectedMethods.contains(method)) {
            retval = true;
        }

        return retval;
    }

    public boolean isProtectedPageAndMethod(String page, String method) {
        return (isProtectedPage(page) && isProtectedMethod(method));
    }

    public boolean isProtectedPageAndMethod(HttpServletRequest request) {
        return isProtectedPageAndMethod(request.getRequestURI(), request.getMethod());
    }

    /**
     * FIXME: taken from Tomcat - ApplicationFilterFactory
     *
     * @param testPath    the pattern to match.
     * @param requestPath the current request path.
     * @return {@code true} if {@code requestPath} matches {@code testPath}.
     */
    protected boolean isUriMatch(String testPath, String requestPath) {
        boolean retval = false;

        /** Case 1: Exact Match **/
        if (testPath.equals(requestPath)) {
            retval = true;
        }

        /** Case 2 - Path Match ("/.../*") **/
        if (testPath.equals("/*")) {
            retval = true;
        }
        if (testPath.endsWith("/*")) {
            if (testPath
                    .regionMatches(0, requestPath, 0, testPath.length() - 2)) {
                if (requestPath.length() == (testPath.length() - 2)) {
                    retval = true;
                } else if ('/' == requestPath.charAt(testPath.length() - 2)) {
                    retval = true;
                }
            }
        }

        /** Case 3 - Extension Match **/
        if (testPath.startsWith("*.")) {
            int slash = requestPath.lastIndexOf('/');
            int period = requestPath.lastIndexOf('.');

            if ((slash >= 0)
                    && (period > slash)
                    && (period != requestPath.length() - 1)
                    && ((requestPath.length() - period) == (testPath.length() - 1))) {
                retval = testPath.regionMatches(2, requestPath, period + 1,
                        testPath.length() - 2);
            }
        }

        return retval;
    }

    protected boolean isUriExactMatch(String testPath, String requestPath) {
        boolean retval = false;

        /** Case 1: Exact Match **/
        if (testPath.equals(requestPath)) {
            retval = true;
        }

        return retval;
    }

}
