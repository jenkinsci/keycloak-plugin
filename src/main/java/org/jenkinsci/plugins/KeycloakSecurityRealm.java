/**
 The MIT License

Copyright (c) 2011 Michael O'Cleirigh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.



 */
package org.jenkinsci.plugins;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.cert.X509Certificate;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.ServerRequest.HttpFailure;
import org.keycloak.adapters.rotation.AdapterRSATokenVerifier;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.LogoutError;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import net.sf.json.JSONObject;

/**
 *
 * Implementation of the AbstractPasswordBasedSecurityRealm that uses keycloak
 * oauth for sso.
 *
 * This is based on the MySQLSecurityRealm from the mysql-auth-plugin written by
 * Alex Ackerman.
 * 
 * @author Mohammad Nadeem, devlauer
 */
public class KeycloakSecurityRealm extends SecurityRealm {

	private static final String JENKINS_LOGIN_URL = "securityRealm/commenceLogin";
	/**
	 * The default URL to finish the login process of this plugin
	 */
	public static final String JENKINS_FINISH_LOGIN_URL = "securityRealm/finishLogin";

	/**
	 * This constant is used to save the state of an authenticated session. If the
	 * login process starts it is set to true, if a logout process is initiated it
	 * is set to false.
	 */
	public static final String AUTH_REQUESTED = "AUTH_REQUESTED";

	private static final Logger LOGGER = Logger.getLogger(KeycloakSecurityRealm.class.getName());

	private static final String REFERER_ATTRIBUTE = KeycloakSecurityRealm.class.getName() + ".referer";

	private transient KeycloakDeployment keycloakDeployment;

	private transient RefreshFilter filter;

	/**
	 * Constructor
	 * 
	 * @throws IOException
	 *             -
	 */
	@DataBoundConstructor
	public KeycloakSecurityRealm() throws IOException {
		super();
		createFilter();
	}

	/*
	 * hudson.security.SecurityRealm.createFilter(FilterConfig) extension point is
	 * not used to leave this kind of handling unchanged. Hence, we are sticking
	 * with the hudson.util.PluginServletFilter.addFilter(Filter) path.
	 */
	synchronized void createFilter() {
		// restarts on things like plugin upgrade bypassed the call to the
		// constructor, so filter initialization
		// has to be driven in-line; note, after initial bring up, the filter
		// variable will be set after subsequent
		// jenkins restarts, but the addFilter call needs to be made on each
		// restart, so we check flag to see if the filter
		// has been ran through at least once
		if (filter == null || !filter.isInitCalled()) {
			try {
				LOGGER.log(Level.INFO, "Create Filter");
				filter = new RefreshFilter();
				hudson.util.PluginServletFilter.addFilter(filter);
			} catch (ServletException e) {
				LOGGER.log(Level.SEVERE, "createFilter", e);
			}
		}
	}

	/**
	 * @param request
	 *            the Jenkins request
	 * @param response
	 *            the Jenkins response
	 * @param referer
	 *            the referrer
	 * @return {@link HttpResponse} the response
	 * @throws IOException
	 */
	public HttpResponse doCommenceLogin(StaplerRequest request, StaplerResponse response,
			@Header("Referer") final String referer) throws IOException {
		request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

		String scopeParam = TokenUtil.attachOIDCScope(null);
		String redirect = redirectUrl(request);

		String state = UUID.randomUUID().toString();

		String authUrl = getKeycloakDeployment().getAuthUrl().clone()
				.queryParam(OAuth2Constants.CLIENT_ID, getKeycloakDeployment().getResourceName())
				.queryParam(OAuth2Constants.REDIRECT_URI, redirect).queryParam(OAuth2Constants.STATE, state)
				.queryParam(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
				.queryParam(OAuth2Constants.SCOPE, scopeParam).build().toString();
		request.getSession().setAttribute(AUTH_REQUESTED, Boolean.valueOf(true));
		createFilter();
		return new HttpRedirect(authUrl);

	}

	private String redirectUrl(StaplerRequest request) {
		String refererURL = request.getReferer();
		String requestURL = request.getRequestURL().toString();
		// if a reverse proxy with ssl is used, the redirect should point to
		// https
		if (refererURL != null && requestURL != null && refererURL.startsWith("https:")
				&& requestURL.startsWith("http:")) {
			requestURL = requestURL.replace("http:", "https:");
		}
		KeycloakUriBuilder builder = KeycloakUriBuilder.fromUri(requestURL).replacePath(request.getContextPath())
				.replaceQuery(null).path(JENKINS_FINISH_LOGIN_URL);
		String redirect = builder.toTemplate();
		return redirect;
	}

	private KeycloakDeployment resolveDeployment(KeycloakDeployment baseDeployment, HttpServletRequest request) {
		ServletFacade facade = new ServletFacade(request);
		return new AdapterDeploymentContext(baseDeployment).resolveDeployment(facade);
	}

	/**
	 * This is where the user comes back to at the end of the OpenID redirect
	 * ping-pong.
	 * 
	 * @param request
	 *            the Jenkins request
	 * @return {@link HttpResponse} the response
	 * @throws IOException
	 */
	public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {

		String redirect = redirectUrl(request);

		try {
			LOGGER.log(Level.FINE, "Code" + request.getParameter(OAuth2Constants.CODE));
			LOGGER.log(Level.FINE, "Redirect" + redirect);

			KeycloakDeployment resolvedDeployment = resolveDeployment(getKeycloakDeployment(), request);

			LOGGER.log(Level.FINE, "TokenURL" + resolvedDeployment.getTokenUrl());

			AccessTokenResponse tokenResponse = ServerRequest.invokeAccessCodeToToken(resolvedDeployment,
					request.getParameter(OAuth2Constants.CODE), redirect, null);

			String tokenString = tokenResponse.getToken();
			String idTokenString = tokenResponse.getIdToken();
			String refreshToken = tokenResponse.getRefreshToken();

			AccessToken token = AdapterRSATokenVerifier.verifyToken(tokenString, resolvedDeployment);
			if (idTokenString != null) {
				JWSInput input = new JWSInput(idTokenString);

				IDToken idToken = input.readJsonContent(IDToken.class);
				SecurityContextHolder.getContext()
						.setAuthentication(new KeycloakAuthentication(idToken, token, refreshToken, tokenResponse));

				User currentUser = User.current();
				if (currentUser != null) {
					currentUser.setFullName(idToken.getPreferredUsername());

					if (!currentUser.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {
						currentUser.addProperty(new Mailer.UserProperty(idToken.getEmail()));
					}
				}
			}

		} catch (Exception e) {
			HttpFailure hf = null;
			LOGGER.log(Level.SEVERE, "Authentication Exception ", e);
			if (e instanceof HttpFailure) {
				hf = (HttpFailure) e;
			}
			Throwable cause = e.getCause();
			if (cause != null) {
				LOGGER.log(Level.SEVERE, "Original exception", cause);
				if (cause instanceof HttpFailure) {
					hf = (HttpFailure) cause;
				}
			}
			if (hf != null) {
				LOGGER.log(Level.SEVERE, "Failure Message" + ((HttpFailure) e).getError());
				LOGGER.log(Level.SEVERE, "Failure HTTP Status" + ((HttpFailure) e).getStatus());
			}

		}

		String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
		if (referer != null) {
			LOGGER.log(Level.FINEST, "Redirecting to " + referer);
			return HttpResponses.redirectTo(referer);
		}
		return HttpResponses.redirectToContextRoot();
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see hudson.security.SecurityRealm#allowsSignup()
	 */
	@Override
	public boolean allowsSignup() {
		return false;
	}

	@Override
	public SecurityComponents createSecurityComponents() {
		SecurityComponents sc = new SecurityComponents(new AuthenticationManager() {
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				if (authentication instanceof KeycloakAuthentication) {
					return authentication;
				}
				throw new BadCredentialsException("Unexpected authentication type: " + authentication);
			}
		});
		return sc;
	}

	@Override
	public String getLoginUrl() {
		return JENKINS_LOGIN_URL;
	}

	@Override
	public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
		final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof KeycloakAuthentication) {
			KeycloakAuthentication keycloakAuthentication = (KeycloakAuthentication) authentication;
			try {
				ServerRequest.invokeLogout(getKeycloakDeployment(), keycloakAuthentication.getRefreshToken());
			} catch (HttpFailure e) {
				LOGGER.log(Level.SEVERE, "Logout Exception ", e);
			}
		}
		req.getSession().setAttribute(AUTH_REQUESTED, Boolean.valueOf(false));
		super.doLogout(req, rsp);
	}

	/**
	 * Descriptor definition for Jenkins
	 * 
	 * @author dev.lauer@elnarion.de
	 *
	 */
	@Extension
	public static class DescriptorImpl extends Descriptor<SecurityRealm> {

		private String keycloakJson = "";
		private boolean keycloakValidate = false;
		private boolean keycloakRespectAccessTokenTimeout = true;

		@Override
		public String getHelpFile() {
			return "/plugin/keycloak/help/help-security-realm.html";
		}

		@Override
		public String getDisplayName() {
			return "Keycloak Authentication Plugin";
		}

		/**
		 * Constructor
		 */
		public DescriptorImpl() {
			load();
		}

		/**
		 * Validator for keycloakJson
		*/
		public FormValidation doCheckKeycloakJson(@QueryParameter String value) throws ServletException {
			try {
				if (value != null && !value.isEmpty()) {
					JsonSerialization.readValue(value, AdapterConfig.class);
				}
			} catch (IOException ex) {
				return FormValidation.error("Invalid adapter config");
			}
			return FormValidation.ok();
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject json) throws hudson.model.Descriptor.FormException {
			json = json.getJSONObject("keycloak");
			keycloakJson = json.getString("keycloakJson");
			// if json contains keycloakvalidate then keycloakvalidate is true
			if (json.containsKey("keycloakValidate")) {
				LOGGER.log(Level.FINE, "Keycloakvalidate set to true");
				keycloakValidate = true;
				JSONObject validate = json.getJSONObject("keycloakValidate");
				if (validate.containsKey("keycloakRespectAccessTokenTimeout")) {
					keycloakRespectAccessTokenTimeout = validate.getBoolean("keycloakRespectAccessTokenTimeout");
					LOGGER.log(Level.FINE,
							"Respect access token timeout is set to " + keycloakRespectAccessTokenTimeout);
				}
			} else {
				keycloakValidate = false;
				keycloakRespectAccessTokenTimeout = true;
			}
			save();
			return true;
		}

		/**
		 * Returns the keycloak configuration
		 * 
		 * @return {@link String} the configuration string
		 */
		public String getKeycloakJson() {
			return keycloakJson;
		}

		/**
		 * Sets the keycloak json configuration string
		 * 
		 * @param keycloakJson
		 *            the configuration
		 */
		public void setKeycloakJson(String keycloakJson) {
			this.keycloakJson = keycloakJson;
		}

		@Override
		public SecurityRealm newInstance(StaplerRequest req, JSONObject formData)
				throws hudson.model.Descriptor.FormException {
			return super.newInstance(req, formData);
		}

		/**
		 * Returns the configuration parameter for the authentication check on each
		 * request
		 * 
		 * @return {@link Boolean} if true, authentication is checked on each request
		 */
		public boolean isKeycloakValidate() {
			return keycloakValidate;
		}

		/**
		 * Sets the configuration parameter for the authentication check
		 * 
		 * @param keycloakValidate
		 *            {@link Boolean} if true authentication is checked on each request
		 */
		public void setKeycloakValidate(boolean keycloakValidate) {
			this.keycloakValidate = keycloakValidate;
		}

		/**
		 * Returns the configuration parameter for the access token check
		 * 
		 * @return {@link Boolean} whether the expiration of the access token should be
		 *         checked or not before a token refresh
		 */
		public boolean isKeycloakRespectAccessTokenTimeout() {
			return keycloakRespectAccessTokenTimeout;
		}

		/**
		 * Sets the configuration parameter for the access token check
		 * 
		 * @param keycloakRespectAccessTokenTimeout
		 *            {@link Boolean} whether the expiration of the access token should
		 *            be checked or not before a token refresh
		 */
		public void setKeycloakRespectAccessTokenTimeout(boolean keycloakRespectAccessTokenTimeout) {
			this.keycloakRespectAccessTokenTimeout = keycloakRespectAccessTokenTimeout;
		}
	}

	public DescriptorImpl getDescriptor() {
		return (DescriptorImpl) super.getDescriptor();

	}

	/**
	 * Returns the keycloak json configuration
	 * 
	 * @return {@link String} the json configuration
	 */
	public String getKeycloakJson() {
		return getDescriptor().getKeycloakJson();
	}

	/**
	 * Returns true if authentication should be checked on each response
	 * 
	 * @return {@link Boolean}
	 */
	public boolean checkKeycloakOnEachRequest() {
		return getDescriptor().isKeycloakValidate();
	}

	/**
	 * Returns true if the access token should be only refreshed after its timeout
	 * 
	 * @return {@link Boolean}
	 */
	public boolean respectAccessTokenTimeout() {
		return getDescriptor().isKeycloakRespectAccessTokenTimeout();
	}

	/**
	 * Returns the current KeycloakDeployment configuration.
	 * 
	 * @return {@link KeycloakDeployment} the keycloak configuration
	 * @throws IOException
	 */
	public synchronized KeycloakDeployment getKeycloakDeployment() throws IOException {
		if (keycloakDeployment == null || keycloakDeployment.getClient() == null) {
			AdapterConfig adapterConfig = JsonSerialization.readValue(getKeycloakJson(), AdapterConfig.class);
			keycloakDeployment = KeycloakDeploymentBuilder.build(adapterConfig);
		}
		return keycloakDeployment;
	}

	/**
	 * @author dev.lauer@elnarion.de
	 *
	 */
	public static class ServletFacade implements OIDCHttpFacade {

		private final HttpServletRequest servletRequest;

		private ServletFacade(HttpServletRequest servletRequest) {
			this.servletRequest = servletRequest;
		}

		@Override
		public KeycloakSecurityContext getSecurityContext() {
			throw new IllegalStateException("Not yet implemented");
		}

		@Override
		public Request getRequest() {
			return new Request() {

				@Override
				public String getFirstParam(String param) {
					return servletRequest.getParameter(param);
				}

				@Override
				public String getMethod() {
					return servletRequest.getMethod();
				}

				@Override
				public String getURI() {
					return servletRequest.getRequestURL().toString();
				}

				@Override
				public String getRelativePath() {
					return servletRequest.getServletPath();
				}

				@Override
				public boolean isSecure() {
					return servletRequest.isSecure();
				}

				@Override
				public String getQueryParamValue(String param) {
					return servletRequest.getParameter(param);
				}

				@Override
				public Cookie getCookie(String cookieName) {
					return null;
				}

				@Override
				public String getHeader(String name) {
					return servletRequest.getHeader(name);
				}

				@Override
				public List<String> getHeaders(String name) {
					return null;
				}

				@Override
				public InputStream getInputStream() {
					try {
						return servletRequest.getInputStream();
					} catch (IOException ioe) {
						throw new RuntimeException(ioe);
					}
				}

				@Override
				public String getRemoteAddr() {
					return servletRequest.getRemoteAddr();
				}

				@Override
				public void setError(AuthenticationError error) {
					servletRequest.setAttribute(AuthenticationError.class.getName(), error);

				}

				@Override
				public void setError(LogoutError error) {
					servletRequest.setAttribute(LogoutError.class.getName(), error);
				}

			};
		}

		@Override
		public Response getResponse() {
			throw new IllegalStateException("Not yet implemented");
		}

		@Override
		public X509Certificate[] getCertificateChain() {
			throw new IllegalStateException("Not yet implemented");
		}
	}

}
