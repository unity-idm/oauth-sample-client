package io.imunity.oauthsampleclient.web;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;

import io.imunity.oauthsampleclient.config.ClientDefaults;
import io.imunity.oauthsampleclient.dpop.DPoPKeyType;
import io.imunity.oauthsampleclient.web.OAuthController.OAuthForm;

/**
 * The start screen form is pre-filled from the configured defaults, with the query parameters of the URL
 * overriding them field by field, so that a filled in form can be shared as a link or bookmarked.
 */
class OAuthControllerIndexBindingTest
{
	private OAuthController controller;

	/**
	 * The defaults deliberately differ from the shipped ones - all of the flow options are enabled and the
	 * DPoP key is not the EC default - so that no assertion below can pass by coincidence.
	 */
	@BeforeEach
	void setup()
	{
		ClientDefaults defaults = new ClientDefaults();
		defaults.setAuthorizationEndpoint("https://as.example/authz");
		defaults.setDeviceAuthorizationEndpoint("https://as.example/device");
		defaults.setTokenEndpoint("https://as.example/token");
		defaults.setUserInfoEndpoint("https://as.example/userinfo");
		defaults.setClientId("configured-client");
		defaults.setClientCred("configured-secret");
		defaults.setScope("openid profile");
		defaults.setExtraParam1("prompt=login");
		defaults.setUsePkce(true);
		defaults.setUseAuthn(true);
		defaults.setUseDpop(true);
		defaults.setDpopKeyType(DPoPKeyType.RSA);
		defaults.setSendDpopJkt(true);
		defaults.setDevicePollingIntervalSeconds(7);
		controller = new OAuthController(defaults);
	}

	@Test
	void shouldOverrideDefaultWithQueryParam()
	{
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setParameter("clientId", "shared-client");
		request.setParameter("scope", "openid email");

		OAuthForm form = renderIndex(request);

		assertThat(form.getClientId()).isEqualTo("shared-client");
		assertThat(form.getScope()).isEqualTo("openid email");
	}

	@Test
	void shouldKeepAllDefaultsWithoutQueryParams()
	{
		OAuthForm form = renderIndex(new MockHttpServletRequest("GET", "/"));

		assertThat(form.getAuthorizationEndpoint()).isEqualTo("https://as.example/authz");
		assertThat(form.getDeviceAuthorizationEndpoint()).isEqualTo("https://as.example/device");
		assertThat(form.getTokenEndpoint()).isEqualTo("https://as.example/token");
		assertThat(form.getUserInfoEndpoint()).isEqualTo("https://as.example/userinfo");
		assertThat(form.getClientId()).isEqualTo("configured-client");
		assertThat(form.getClientCred()).isEqualTo("configured-secret");
		assertThat(form.getScope()).isEqualTo("openid profile");
		assertThat(form.getExtraParam1()).isEqualTo("prompt=login");
		assertThat(form.isUsePkce()).isTrue();
		assertThat(form.isUseAuthn()).isTrue();
		assertThat(form.isUseDpop()).isTrue();
		assertThat(form.getDpopKeyType()).isEqualTo(DPoPKeyType.RSA);
		assertThat(form.isSendDpopJkt()).isTrue();
		assertThat(form.getDevicePollingIntervalSeconds()).isEqualTo(7);
	}

	/**
	 * A shared link carries every field, so an option switched off by the sender must switch it off for the
	 * recipient too, even when their own configuration enables it.
	 */
	@Test
	void shouldDisableOptionEnabledByDefault()
	{
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setParameter("usePkce", "false");
		request.setParameter("useAuthn", "false");
		request.setParameter("useDpop", "false");
		request.setParameter("sendDpopJkt", "false");

		OAuthForm form = renderIndex(request);

		assertThat(form.isUsePkce()).isFalse();
		assertThat(form.isUseAuthn()).isFalse();
		assertThat(form.isUseDpop()).isFalse();
		assertThat(form.isSendDpopJkt()).isFalse();
	}

	/**
	 * A link mangled in transit, or one saved before an enum constant was renamed, still has to open a
	 * usable form: what can not be converted is ignored, the rest is bound.
	 */
	@Test
	void shouldIgnoreUnconvertibleValues()
	{
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setParameter("dpopKeyType", "BOGUS");
		request.setParameter("devicePollingIntervalSeconds", "abc");
		request.setParameter("clientId", "shared-client");

		OAuthForm form = renderIndex(request);

		assertThat(form.getDpopKeyType()).isEqualTo(DPoPKeyType.RSA);
		assertThat(form.getDevicePollingIntervalSeconds()).isEqualTo(7);
		assertThat(form.getClientId()).isEqualTo("shared-client");
	}

	private OAuthForm renderIndex(MockHttpServletRequest request)
	{
		Model model = new ExtendedModelMap();
		assertThat(controller.index(request, model)).isEqualTo("index");
		return (OAuthForm) model.getAttribute("form");
	}
}
