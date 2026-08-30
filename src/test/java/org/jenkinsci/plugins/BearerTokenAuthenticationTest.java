package org.jenkinsci.plugins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.htmlunit.Page;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.GrantedAuthority;

import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;

/**
 * Tests for the {@code Authorization: Bearer <token>} authentication path added
 * to {@link KeycloakSecurityRealm} via {@link BearerTokenFilter}.
 */
public class BearerTokenAuthenticationTest {

	@Rule
	public JenkinsRule j = new JenkinsRule();

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

		Set<String> authorities = auth.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toSet());
		assertTrue("realm role missing: " + authorities, authorities.contains("realm-role"));
		assertTrue("client role missing: " + authorities, authorities.contains("client-role"));
		assertTrue("flat role missing: " + authorities, authorities.contains("flat-role"));
		assertTrue("authenticated authority missing: " + authorities,
				authorities.contains(SecurityRealm.AUTHENTICATED_AUTHORITY2.getAuthority()));
	}

	/**
	 * An unparseable / invalid bearer token must not break request processing:
	 * verification fails, the filter swallows it and the request continues
	 * unauthenticated instead of producing a 500.
	 */
	@Test
	public void invalidBearerToken_degradesGracefully() throws Exception {
		KeycloakSecurityRealm realm = new KeycloakSecurityRealm();
		realm.setKeycloakJson("{"
				+ "\"realm\": \"master\","
				+ "\"auth-server-url\": \"https://keycloak.example.com/auth/\","
				+ "\"ssl-required\": \"external\","
				+ "\"resource\": \"jenkins\","
				+ "\"credentials\": {\"secret\": \"secret-secret-secret\"},"
				+ "\"confidential-port\": 0"
				+ "}");
		Jenkins.get().setSecurityRealm(realm);

		JenkinsRule.WebClient wc = j.createWebClient();
		wc.getOptions().setThrowExceptionOnFailingStatusCode(false);
		wc.addRequestHeader("Authorization", "Bearer not-a-real-token");

		Page page = wc.goTo("whoAmI/api/json", "application/json");
		int status = page.getWebResponse().getStatusCode();
		assertTrue("expected a normal (non-5xx) response, got " + status, status < 500);
		assertFalse("response looks like a Jenkins error page",
				page.getWebResponse().getContentAsString().contains("Stack trace"));
	}
}
