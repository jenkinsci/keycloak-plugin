package org.jenkinsci.plugins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.htmlunit.Page;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.keycloak.representations.AccessToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;

/**
 * Tests for the {@code Authorization: Bearer <token>} authentication path added
 * to {@link KeycloakSecurityRealm} via {@link BearerTokenFilter}, plus the
 * bearer-token constructor of {@link KeycloakAuthentication}.
 */
public class BearerTokenAuthenticationTest {

	@Rule
	public JenkinsRule j = new JenkinsRule();

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	// ---------------------------------------------------------------------
	// KeycloakAuthentication bearer constructor
	// ---------------------------------------------------------------------

	/**
	 * The bearer-token constructor of {@link KeycloakAuthentication} maps the
	 * username and all three role sources (realm roles, a flat {@code roles}
	 * claim and client roles for the adapter resource) from the access token
	 * alone, plus the standard "authenticated" authority.
	 */
	@Test
	@WithoutJenkins
	public void bearerConstructor_mapsIdentityAndRoles() {
		AccessToken token = new AccessToken();
		token.setPreferredUsername("alice");
		token.setRealmAccess(new AccessToken.Access().addRole("realm-role"));
		token.addAccess("jenkins").addRole("client-role");
		token.getOtherClaims().put("roles", List.of("flat-role"));

		KeycloakAuthentication auth = new KeycloakAuthentication(token, "jenkins");

		assertEquals("alice", auth.getName());
		assertTrue(auth.isAuthenticated());

		Set<String> authorities = authorityNames(auth);
		assertTrue("realm role missing: " + authorities, authorities.contains("realm-role"));
		assertTrue("client role missing: " + authorities, authorities.contains("client-role"));
		assertTrue("flat role missing: " + authorities, authorities.contains("flat-role"));
		assertTrue("authenticated authority missing: " + authorities,
				authorities.contains(SecurityRealm.AUTHENTICATED_AUTHORITY2.getAuthority()));
	}

	// ---------------------------------------------------------------------
	// BearerTokenFilter — branches that never reach a Jenkins instance
	// ---------------------------------------------------------------------

	@Test
	@WithoutJenkins
	public void nonHttpRequest_isIgnored() throws Exception {
		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(plainRequest(), null, chain);

		assertTrue("chain must always continue", chain.called);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	@WithoutJenkins
	public void missingOrNonBearerHeader_isIgnored() throws Exception {
		for (String header : new String[] {null, "", "Basic dXNlcjpwYXNz", "Bearer", "Token abc"}) {
			SecurityContextHolder.clearContext();
			RecordingChain chain = new RecordingChain();
			new BearerTokenFilter().doFilter(httpRequest(header), null, chain);

			assertTrue("chain must continue for header " + header, chain.called);
			assertNull("no auth expected for header " + header,
					SecurityContextHolder.getContext().getAuthentication());
		}
	}

	@Test
	@WithoutJenkins
	public void alreadyAuthenticatedRequest_isLeftUntouched() throws Exception {
		Authentication existing = authenticated("bob");
		SecurityContextHolder.getContext().setAuthentication(existing);

		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(httpRequest("Bearer some.jwt.value"), null, chain);

		assertTrue(chain.called);
		assertSame("existing authentication must be preserved",
				existing, SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	@WithoutJenkins
	public void noJenkinsInstance_isIgnored() throws Exception {
		// @WithoutJenkins => Jenkins.getInstanceOrNull() returns null
		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(httpRequest("Bearer some.jwt.value"), null, chain);

		assertTrue(chain.called);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	// ---------------------------------------------------------------------
	// BearerTokenFilter — branches that need a Jenkins with a security realm
	// ---------------------------------------------------------------------

	@Test
	public void nonKeycloakSecurityRealm_isIgnored() throws Exception {
		Jenkins.get().setSecurityRealm(SecurityRealm.NO_AUTHENTICATION);
		SecurityContextHolder.clearContext();

		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(httpRequest("Bearer some.jwt.value"), null, chain);

		assertTrue(chain.called);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void bearerPrefixWithBlankToken_isIgnored() throws Exception {
		Jenkins.get().setSecurityRealm(keycloakRealm());
		SecurityContextHolder.clearContext();

		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(httpRequest("Bearer      "), null, chain);

		assertTrue(chain.called);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void invalidBearerToken_isRejectedAndDegradesGracefully() throws Exception {
		Jenkins.get().setSecurityRealm(keycloakRealm());
		SecurityContextHolder.clearContext();

		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(httpRequest("Bearer not-a-real-token"), null, chain);

		assertTrue("request processing must not be broken by a bad token", chain.called);
		assertNull("verification failed, so no authentication",
				SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void unparseableAdapterConfig_isHandled() throws Exception {
		KeycloakSecurityRealm realm = new KeycloakSecurityRealm();
		realm.setKeycloakJson("{ this is not valid json");
		Jenkins.get().setSecurityRealm(realm);
		SecurityContextHolder.clearContext();

		RecordingChain chain = new RecordingChain();
		new BearerTokenFilter().doFilter(httpRequest("Bearer some.jwt.value"), null, chain);

		assertTrue(chain.called);
		assertNull(SecurityContextHolder.getContext().getAuthentication());
	}

	// ---------------------------------------------------------------------
	// Integration: full servlet stack through htmlunit
	// ---------------------------------------------------------------------

	/**
	 * An invalid bearer token must not break request processing when it flows
	 * through the real filter chain: the request continues unauthenticated
	 * instead of producing a 500.
	 */
	@Test
	public void invalidBearerToken_overHttp_returnsNormalResponse() throws Exception {
		Jenkins.get().setSecurityRealm(keycloakRealm());

		JenkinsRule.WebClient wc = j.createWebClient();
		wc.getOptions().setThrowExceptionOnFailingStatusCode(false);
		wc.addRequestHeader("Authorization", "Bearer not-a-real-token");

		Page page = wc.goTo("whoAmI/api/json", "application/json");
		int status = page.getWebResponse().getStatusCode();
		assertTrue("expected a normal (non-5xx) response, got " + status, status < 500);
		assertFalse("response looks like a Jenkins error page",
				page.getWebResponse().getContentAsString().contains("Stack trace"));
	}

	// ---------------------------------------------------------------------
	// helpers
	// ---------------------------------------------------------------------

	private static Set<String> authorityNames(Authentication auth) {
		return auth.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toSet());
	}

	private static KeycloakSecurityRealm keycloakRealm() throws IOException {
		KeycloakSecurityRealm r = new KeycloakSecurityRealm();
		r.setKeycloakJson("{"
				+ "\"realm\": \"master\","
				+ "\"auth-server-url\": \"https://keycloak.example.com/\","
				+ "\"ssl-required\": \"external\","
				+ "\"resource\": \"jenkins\","
				+ "\"credentials\": {\"secret\": \"secret-secret-secret\"},"
				+ "\"confidential-port\": 0"
				+ "}");
		return r;
	}

	private static Authentication authenticated(String name) {
		AbstractAuthenticationToken token = new AbstractAuthenticationToken(Collections.emptyList()) {
			@Override
			public Object getCredentials() {
				return "";
			}

			@Override
			public Object getPrincipal() {
				return name;
			}

			@Override
			public String getName() {
				return name;
			}
		};
		token.setAuthenticated(true);
		return token;
	}

	/** A {@link ServletRequest} that is not an {@link HttpServletRequest}. */
	private static ServletRequest plainRequest() {
		return (ServletRequest) Proxy.newProxyInstance(
				BearerTokenAuthenticationTest.class.getClassLoader(),
				new Class<?>[] {ServletRequest.class},
				(proxy, method, args) -> defaultReturn(method.getReturnType()));
	}

	/** A minimal {@link HttpServletRequest} that only answers {@code getHeader("Authorization")}. */
	private static HttpServletRequest httpRequest(String authorization) {
		return (HttpServletRequest) Proxy.newProxyInstance(
				BearerTokenAuthenticationTest.class.getClassLoader(),
				new Class<?>[] {HttpServletRequest.class},
				(proxy, method, args) -> {
					if ("getHeader".equals(method.getName()) && args != null && args.length == 1
							&& "Authorization".equals(args[0])) {
						return authorization;
					}
					return defaultReturn(method.getReturnType());
				});
	}

	private static Object defaultReturn(Class<?> type) {
		if (type == boolean.class) {
			return Boolean.FALSE;
		}
		if (type == int.class) {
			return 0;
		}
		if (type == long.class) {
			return 0L;
		}
		return null;
	}

	private static final class RecordingChain implements FilterChain {
		private boolean called;

		@Override
		public void doFilter(ServletRequest request, ServletResponse response) {
			called = true;
		}
	}
}
