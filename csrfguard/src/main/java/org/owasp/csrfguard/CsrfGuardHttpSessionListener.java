package org.owasp.csrfguard;

import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

public class CsrfGuardHttpSessionListener implements HttpSessionListener {

    @Override
    public void sessionCreated(HttpSessionEvent event) {
        HttpSession session = event.getSession();
        CsrfGuard csrfGuard = CsrfGuardFactory.getCsrfGuard();
        csrfGuard.updateToken(session);
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent event) {
        /** nothing to do **/
        CsrfGuardFactory.getCsrfGuard().destoryStorage(event.getSession().getId());
    }

}
