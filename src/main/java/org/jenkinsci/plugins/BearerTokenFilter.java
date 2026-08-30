package org.jenkinsci.plugins;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;

import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Authenticates REST / API requests that present a Keycloak access token as
 * {@code Authorization: Bearer <token>}.
 *
 * <p>The token is verified against the realm using the same adapter deployment
 * the browser flow uses: signature (via the realm JWKS), issuer, expiry and —
 * when {@code verify-token-audience} is enabled in the adapter config — audience.
 * On success the request runs as the token's user for that request only; no HTTP
 * session is created. Any verification failure is logged and the request
 * continues unauthenticated (anonymous), letting Jenkins' normal authorization
 * decide the outcome.
 *
 * <p>The filter is inserted into the security filter chain (see
 * {@link KeycloakSecurityRealm#createFilter(FilterConfig)}) after session
 * integration and the anonymous filter, so the authentication it sets is visible
 * to Jenkins' permission checks.
 */
public class BearerTokenFilter implements Filter {

	private static final Logger LOGGER = Logger.getLogger(BearerTokenFilter.class.getName());
	private static final String BEARER_PREFIX = "Bearer ";

	@Override
	public void init(FilterConfig filterConfig) {
		// no-op
	}

	@Override
	public void destroy() {
		// no-op
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (request instanceof HttpServletRequest) {
			try {
				authenticate((HttpServletRequest) request);
			} catch (RuntimeException e) {
				// Best-effort: any failure leaves the request unauthenticated (anonymous)
				// rather than breaking request processing.
				LOGGER.log(Level.FINE, "Bearer token authentication skipped due to an unexpected error", e);
			}
		}
		chain.doFilter(request, response);
	}

	private void authenticate(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		if (header == null || header.length() <= BEARER_PREFIX.length()
				|| !header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
			return;
		}

		SecurityContext context = SecurityContextHolder.getContext();
		Authentication current = context.getAuthentication();
		if (current != null && current.isAuthenticated()
				&& !(current instanceof AnonymousAuthenticationToken)) {
			// already authenticated by session, API token, etc.
			return;
		}

		Jenkins jenkins = Jenkins.getInstanceOrNull();
		if (jenkins == null) {
			return;
		}
		SecurityRealm securityRealm = jenkins.getSecurityRealm();
		if (!(securityRealm instanceof KeycloakSecurityRealm)) {
			return;
		}

		String tokenString = header.substring(BEARER_PREFIX.length()).trim();
		if (tokenString.isEmpty()) {
			return;
		}

		try {
			KeycloakDeployment deployment = ((KeycloakSecurityRealm) securityRealm).getKeycloakDeployment();
			AccessToken token = AdapterTokenVerifier.verifyToken(tokenString, deployment);
			KeycloakAuthentication authentication =
					new KeycloakAuthentication(token, deployment.getResourceName());
			context.setAuthentication(authentication);
			LOGGER.log(Level.FINE, "Bearer token accepted for user {0}", authentication.getName());
		} catch (VerificationException e) {
			LOGGER.log(Level.FINE, "Bearer token rejected: {0}", e.getMessage());
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "Could not load Keycloak deployment for bearer token verification", e);
		}
	}
}
