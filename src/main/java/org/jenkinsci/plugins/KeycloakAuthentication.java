package org.jenkinsci.plugins;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import hudson.security.SecurityRealm;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * 
 * @author Mohammad Nadeem
 * @author dev.lauer@elnarion.de
 *
 */
public class KeycloakAuthentication extends AbstractAuthenticationToken {


	private static final long serialVersionUID = 1L;
	private final String userName;
	private String refreshToken;
	private String accessToken;
	private transient AccessTokenResponse accessTokenResponse = null;
	private Calendar lastRefresh = Calendar.getInstance();
	
	/**
	 * Constructor
	 * @param idToken the keycloak id token
	 * @param accessToken the keycloak access token
	 * @param refreshToken the keycloak refresh token
	 * @param tokenResponse the {@link AccessTokenResponse}
	 */
	public KeycloakAuthentication(IDToken idToken, AccessToken accessToken, String refreshToken, AccessTokenResponse tokenResponse, String resourceName) {
		super(buildRoles(accessToken, resourceName));
		this.userName = idToken.getPreferredUsername();
		this.setRefreshToken(refreshToken);
		this.setAccessTokenResponse(tokenResponse);
		setAuthenticated(true);
	}

	/**
	 * Constructor for stateless bearer-token (REST API) authentication. The
	 * identity and authorities come solely from an already-verified Keycloak
	 * access token; there is no ID token, refresh token or session.
	 *
	 * @param accessToken  the verified Keycloak access token
	 * @param resourceName the adapter resource / client name, used to map client roles
	 */
	public KeycloakAuthentication(AccessToken accessToken, String resourceName) {
		super(buildRoles(accessToken, resourceName));
		this.userName = accessToken.getPreferredUsername();
		setAuthenticated(true);
	}

	@SuppressWarnings("unchecked")
	private static Collection<GrantedAuthority> buildRoles(AccessToken accessToken, String resourceName) {
		List<GrantedAuthority> roles = new ArrayList<>();

		if (accessToken != null && accessToken.getRealmAccess() != null) {
			for (String role : accessToken.getRealmAccess().getRoles()) {
				roles.add(new SimpleGrantedAuthority(role));
			}
		}

		if(accessToken != null && accessToken.getOtherClaims().containsKey("roles")) {
			for(String role : (List<String>) accessToken.getOtherClaims().get("roles")) {
				roles.add(new SimpleGrantedAuthority(role));
			}
		}

		if (accessToken != null && accessToken.getResourceAccess().containsKey(resourceName)) {
			for (String role : accessToken.getResourceAccess().get(resourceName).getRoles()) {
				roles.add(new SimpleGrantedAuthority(role));
			}
		}

		roles.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);
		return roles;
	}

	@Override
	public String getName() {
		return this.userName;
	}

	@Override
	public Object getCredentials() {
		return ""; // do not expose the credential
	}

	@Override
	public Object getPrincipal() {
		return this.userName;
	}

	/**
	 * Get the keycloak refresh token
	 * @return {@link String} the refresh token
	 */
	public String getRefreshToken() {
		return refreshToken;
	}

	/**
	 * Get the keycloak access token
	 * @return {@link String} the access token
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * Sets the refresh token
	 * @param refreshToken {@link String}
	 */
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	/**
	 * Sets the access token
	 * @param accessToken {@link String}
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	/**
	 * Returns the latest AccessTokenResponse
	 * 
	 * @return {@link AccessTokenResponse}
	 */
	public AccessTokenResponse getAccessTokenResponse() {
		return accessTokenResponse;
	}

	/**
	 * Sets the latest AccessTokenResponse
	 * @param accessTokenResponse
	 */
	public void setAccessTokenResponse(AccessTokenResponse accessTokenResponse) {
		this.accessTokenResponse = accessTokenResponse;
		setRefreshToken(accessTokenResponse.getRefreshToken());
		setLastRefresh(new Date());
	}

	/**
	 * Get the date the token is from
	 * @return {@link Date}
	 */
	public Date getLastRefresh() {
		return lastRefresh.getTime();
	}

	/**
	 * Get the date the token is from
	 * @return {@link Calendar}
	 */
	public Calendar getLastRefreshDateAsCalendar() {
		return lastRefresh;
	}
	/**
	 * Set the date the token is from
	 * @param lastRefresh
	 */
	public void setLastRefresh(Date lastRefresh) {
		this.lastRefresh.setTime(lastRefresh);
	}
	
	/**
	 * Checks whether the refresh token is expired or not.
	 * 
	 * @return boolean - the result of the check
	 */
	public boolean isRefreshExpired()
	{
		if(accessTokenResponse==null)
			return true;
		Calendar compareDate = Calendar.getInstance();
		compareDate.add(Calendar.SECOND, (int)(accessTokenResponse.getRefreshExpiresIn())*-1);
		return compareDate.after(lastRefresh);
	}
	
	/**
	 * Checks whether the access token is expired or not.
	 * 
	 * @return boolean - the result of the check
	 */
	public boolean isAccessExpired()
	{
		if(accessTokenResponse==null)
			return true;
		Calendar compareDate = Calendar.getInstance();
		compareDate.add(Calendar.SECOND, (int)(accessTokenResponse.getExpiresIn())*-1);
		return compareDate.after(lastRefresh);
	}	

}
