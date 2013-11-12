package org.owasp.csrfguard.http;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.owasp.csrfguard.CsrfGuard;

public class InterceptRedirectResponse extends HttpServletResponseWrapper {

	private HttpServletResponse response = null;

	private CsrfGuard csrfGuard;

	private HttpServletRequest request;

	public InterceptRedirectResponse(HttpServletResponse response, HttpServletRequest request, CsrfGuard csrfGuard) {
		super(response);
		this.response = response;
		this.request = request;
		this.csrfGuard = csrfGuard;
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		// Remove CR and LF characters to prevent CRLF injection
		String encodedLocation = location.replaceAll("(\\r|\\n|%0D|%0A|%0a|%0d)", "");
		
		/** ensure token included in redirects **/
		if (!encodedLocation.contains("://") && csrfGuard.isProtectedPageAndMethod(encodedLocation, "GET")) {
			/** update tokens **/
			csrfGuard.updateTokens(request);
			
			StringBuilder sb = new StringBuilder();

			if (!encodedLocation.startsWith("/")) {
				sb.append(request.getContextPath() + "/" + encodedLocation);
			} else {
				sb.append(encodedLocation);
			}
			
			if (encodedLocation.contains("?")) {
				sb.append('&');
			} else {
				sb.append('?');
			}

			// remove any query parameters from the encodedLocation
			String encodedLocationUri = encodedLocation.split("\\?", 2)[0];

			sb.append(csrfGuard.getTokenName());
			sb.append('=');
			sb.append(csrfGuard.getTokenValue(request, encodedLocationUri));
			
			response.sendRedirect(sb.toString());
		} else {
			response.sendRedirect(encodedLocation);
		}
	}
}
