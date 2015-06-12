package org.owasp.csrfguard.action;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardException;
import org.owasp.csrfguard.nostatus.redis.RedisClient;
import org.owasp.csrfguard.util.RandomGenerator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by Administrator on 2015/6/11.
 */
public class RedisRotate extends AbstractAction {

    @Override
    public void execute(HttpServletRequest request, HttpServletResponse response, CsrfGuardException csrfe, CsrfGuard csrfGuard) throws CsrfGuardException {
        HttpSession session = request.getSession(false);

        if (session != null) {
            updateSessionToken(session, csrfGuard);

            if (csrfGuard.isTokenPerPageEnabled()) {
                updatePageTokens(session, csrfGuard);
            }
        }
    }

    private void updateSessionToken(HttpSession session, CsrfGuard csrfGuard) throws CsrfGuardException {
        String token = null;

        try {
            token = RandomGenerator.generateRandomId(csrfGuard.getPrng(),
                    csrfGuard.getTokenLength());
        } catch (Exception e) {
            throw new CsrfGuardException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
        }

        RedisClient.getInstance().set(csrfGuard.getSessionKey(session.getId()), token);
    }

    private void updatePageTokens(HttpSession session, CsrfGuard csrfGuard) throws CsrfGuardException {
        Map<String, String> pageTokens = RedisClient.getInstance().getHash(session.getId() + CsrfGuard.PAGE_TOKENS_KEY);
        List<String> pages = new ArrayList<String>();

        if (pageTokens != null) {
            pages.addAll(pageTokens.keySet());
        }

        for (String page : pages) {
            String token = null;

            try {
                token = RandomGenerator.generateRandomId(csrfGuard.getPrng(), csrfGuard.getTokenLength());
            } catch (Exception e) {
                throw new CsrfGuardException(String.format("unable to generate the random token - %s", e.getLocalizedMessage()), e);
            }

            RedisClient.getInstance().setHash(session.getId() + CsrfGuard.PAGE_TOKENS_KEY, page, token);
        }
    }
}
