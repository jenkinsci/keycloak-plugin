package org.jenkinsci.plugins;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextArea;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.model.CNode;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import static io.jenkins.plugins.casc.misc.Util.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class KeycloakSecurityRealmTest {
    @Rule
    public JenkinsConfiguredWithCodeRule chain = new JenkinsConfiguredWithCodeRule();

    @Rule
	public JenkinsRule j = new JenkinsRule();

    @Test
    @ConfiguredWithCode("casc.yaml")
    public void configure_keycloak() {
        final Jenkins jenkins = Jenkins.getInstanceOrNull();
        final KeycloakSecurityRealm securityRealm = (KeycloakSecurityRealm) jenkins.getSecurityRealm();
        assertEquals("{\n" +
			"  \"realm\": \"master\",\n" +
			"  \"auth-server-url\": \"https://keycloak.example.com/auth/\",\n" +
			"  \"ssl-required\": \"external\",\n" +
			"  \"resource\": \"ci-example-com\",\n" +
			"  \"credentials\": {\n" +
			"    \"secret\": \"secret-secret-secret\"\n" +
			"  },\n" +
			"  \"confidential-port\": 0\n" +
			"}", securityRealm.getKeycloakJson());
    }

    @Test
    public void export_casc_keycloak() throws Exception {
        KeycloakSecurityRealm ksr = new KeycloakSecurityRealm();
        ksr.setKeycloakJson("{\"realm\": \"master\",\"auth-server-url\": \"https://keycloak.example.com/auth/\",\"ssl-required\": \"external\",\"resource\": \"ci-example-com\",\"credentials\": {\"secret\": \"secret-secret-secret\"},\"confidential-port\": 0}");
        Jenkins.getInstanceOrNull().setSecurityRealm(ksr);

        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getJenkinsRoot(context).get("securityRealm").asMapping().get("keycloak");

        String exported = toYamlString(yourAttribute);

        String expected = toStringFromYamlFile(this, "KeycloakYamlExport.yaml");

        assertEquals(expected, exported);
    }

	@Test
	public void testFormSubmitKeycloakConfig() throws Exception {

		final String keycloakJson = "{\"realm\": \"master\"," +
			"\"auth-server-url\": \"https://keycloak.example.com/auth/\"," +
			"\"ssl-required\": \"external\"," +
			"\"resource\": \"ci-example-com\"," +
			"\"credentials\": {\"secret\": \"secret-secret-secret\"}," +
			"\"confidential-port\": 0}";

		KeycloakSecurityRealm keycloakSecurityRealm = new KeycloakSecurityRealm();
		keycloakSecurityRealm.setKeycloakJson(keycloakJson);
		j.jenkins.setSecurityRealm(keycloakSecurityRealm);

		WebClient wc = j.createWebClient();

		HtmlPage page = wc.goTo("configureSecurity");
		HtmlForm form = page.getFormByName("config");

		// verify config.jelly is displayed
		HtmlTextArea keycloakJsonField = page.getElementByName("_.keycloakJson");
		assertNotNull(keycloakJsonField);
		assertEquals(keycloakJson, keycloakJsonField.getText());
		keycloakJsonField.setText("");
		j.submit(form);

		KeycloakSecurityRealm newRealm = (KeycloakSecurityRealm) j.jenkins.getSecurityRealm();

		assertEquals(keycloakSecurityRealm.getKeycloakJson(), newRealm.getKeycloakJson());
	}
}
