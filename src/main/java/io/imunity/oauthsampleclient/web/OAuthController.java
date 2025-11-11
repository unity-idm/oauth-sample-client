package io.imunity.oauthsampleclient.web;


import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

import ch.qos.logback.classic.Logger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;

@Controller
public class OAuthController
{
	private static final Logger log = (Logger) org.slf4j.LoggerFactory.getLogger(OAuthController.class);
	private static final ObjectWriter PRETTY = new ObjectMapper().writerWithDefaultPrettyPrinter();
	public static final String SESSION_STATE = "oauth_state";
	public static final String SESSION_CODE_VERIFIER = "oauth_code_verifier";
	public static final String SESSION_TOKEN_ENDPOINT = "oauth_token_endpoint";
	public static final String SESSION_CLIENT_ID = "oauth_client_id";
	public static final String SESSION_USE_PKCE = "oauth_use_pkce";

	@GetMapping("/")
	public String index(HttpServletRequest request, Model model)
	{
		model.addAttribute("form", new OAuthForm());
		model.addAttribute("redirectUri", computeRedirectUri(request));
		return "index";
	}

	@PostMapping("/start")
	public String startAuth(@ModelAttribute("form") OAuthForm form, HttpServletRequest request, HttpSession session,
			Model model) throws Exception
	{
		String redirectUri = computeRedirectUri(request);
		State state = new State();
		CodeVerifier codeVerifier = null;

		if (form.usePkce())
		{
			codeVerifier = new CodeVerifier();
		}

		// Store context in session
		session.setAttribute(SESSION_STATE, state.getValue());
		session.setAttribute(SESSION_TOKEN_ENDPOINT, form.tokenEndpoint());
		session.setAttribute(SESSION_CLIENT_ID, form.clientId());
		session.setAttribute(SESSION_USE_PKCE, form.usePkce());
		if (codeVerifier != null)
		{
			session.setAttribute(SESSION_CODE_VERIFIER, codeVerifier.getValue());
		}

		URI authzEndpoint = new URI(form.authorizationEndpoint());
		AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(new ResponseType("code"),
				new ClientID(form.clientId()))
					.redirectionURI(new URI(redirectUri))
					.state(state);

		if (StringUtils.hasText(form.scope()))
		{
			builder.scope(Scope.parse(form.scope()));
		}
		if (codeVerifier != null)
		{
			builder.codeChallenge(codeVerifier, CodeChallengeMethod.S256);
		}
		if (StringUtils.hasText(form.extraParam1))
		{
			String[] params = form.extraParam1.split("=");
			builder.customParameter(params[0], params[1]);
		}

		AuthorizationRequest authRequest = builder.endpointURI(authzEndpoint).build();
		String redirect = authRequest.toURI().toString();
		return "redirect:" + redirect;
	}

	@GetMapping("/callback")
	public String callback(@RequestParam(name = "code", required = false) String code,
			@RequestParam(name = "state", required = false) String stateParam,
			@RequestParam(name = "error", required = false) String error,
			@RequestParam(name = "error_description", required = false) String errorDescription,
			HttpServletRequest request, HttpSession session, Model model) throws Exception
	{
		String expectedState = (String) session.getAttribute(SESSION_STATE);
		if (!StringUtils.hasText(expectedState) || !Objects.equals(expectedState, stateParam))
		{
			model.addAttribute("rawResponse", "State mismatch or missing session. Expected: " + expectedState
					+ ", got: " + stateParam);
			return "result";
		}
		if (StringUtils.hasText(error))
		{
			model.addAttribute("rawResponse", "Error returned from authorization endpoint: " + error + " - "
					+ errorDescription);
			return "result";
		}

		String tokenEndpoint = (String) session.getAttribute(SESSION_TOKEN_ENDPOINT);
		String clientId = (String) session.getAttribute(SESSION_CLIENT_ID);
		boolean usePkce = Boolean.TRUE.equals(session.getAttribute(SESSION_USE_PKCE));
		String verifier = (String) session.getAttribute(SESSION_CODE_VERIFIER);

		String redirectUri = computeRedirectUri(request);

		AuthorizationCodeGrant grant;
		if (usePkce)
		{
			grant = new AuthorizationCodeGrant(new AuthorizationCode(code), new URI(redirectUri),
					new CodeVerifier(verifier));
		} else
		{
			grant = new AuthorizationCodeGrant(new AuthorizationCode(code), new URI(redirectUri));
		}

		com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(
				new URI(tokenEndpoint), new ClientID(clientId), grant);

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		HTTPResponse httpResponse;
		try
		{
			configureInsecureTLS(httpRequest);
			httpResponse = httpRequest.send();
		} catch (Exception e)
		{
			log.error("Error sending token request", e);
			model.addAttribute("rawResponse", "Error sending token request: " + e.getMessage());
			return "result";
		}

		String body = httpResponse.getBody();
		model.addAttribute("rawResponse", "HTTP " + httpResponse.getStatusCode() + "\n\n" + body);

		try
		{
			TokenResponse tr = OIDCTokenResponse.parse(httpResponse);
			if (tr.indicatesSuccess())
			{
				AccessTokenResponse successResponse = tr.toSuccessResponse();
				Tokens tokens = successResponse.getTokens();

				model.addAttribute("accessToken", tokens.getAccessToken() != null
						? PRETTY.writeValueAsString(tokens.getAccessToken().toJSONObject()) : null);


				if (successResponse instanceof OIDCTokenResponse oidcResponse)
				{
					JWT idToken = oidcResponse.getOIDCTokens().getIDToken();
					if (idToken != null)
					{
						String stringRep = String.format("header: %s\n\nbody: %s",
								PRETTY.writeValueAsString(idToken.getHeader().toJSONObject()),
								PRETTY.writeValueAsString(idToken.getJWTClaimsSet().toJSONObject()));
						model.addAttribute("idToken", stringRep);
					}
				}
			} else
			{
				model.addAttribute("oauthError", tr.toErrorResponse().toJSONObject().toJSONString());
			}
		} catch (Exception e)
		{
			log.error("Error parsing response", e);
		}

		return "result";
	}

	private String computeRedirectUri(HttpServletRequest request)
	{
		String scheme = request.getHeader("X-Forwarded-Proto");
		if (!StringUtils.hasText(scheme))
			scheme = request.getScheme();
		String host = request.getHeader("X-Forwarded-Host");
		if (!StringUtils.hasText(host))
			host = request.getServerName() + (includePort(scheme, request.getServerPort()) ? ":" + request.getServerPort() : "");
		try
		{
			return new URI(scheme, null, host.contains(":") ? host.split(":")[0] : host,
					parsePort(host, request.getServerPort(), scheme), "/callback", null, null).toString();
		} catch (URISyntaxException e)
		{
			StringBuilder sb = new StringBuilder();
			sb.append(scheme).append("://").append(request.getServerName());
			if (includePort(scheme, request.getServerPort()))
				sb.append(":").append(request.getServerPort());
			sb.append("/callback");
			return sb.toString();
		}
	}

	private boolean includePort(String scheme, int port)
	{
		return !("http".equalsIgnoreCase(scheme) && port == 80) && !("https".equalsIgnoreCase(scheme) && port == 443);
	}

	private int parsePort(String hostHeader, int defaultPort, String scheme)
	{
		if (hostHeader != null && hostHeader.contains(":"))
		{
			try
			{
				return Integer.parseInt(hostHeader.substring(hostHeader.lastIndexOf(':') + 1));
			} catch (NumberFormatException ignored)
			{
			}
		}
		return defaultPort == 0 ? ("https".equalsIgnoreCase(scheme) ? 443 : 80) : defaultPort;
	}

	private static void configureInsecureTLS(HTTPRequest httpRequest)
	{
		try
		{
			javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] {
					new javax.net.ssl.X509TrustManager()
					{
						public java.security.cert.X509Certificate[] getAcceptedIssuers()
						{
							return new java.security.cert.X509Certificate[0];
						}

						public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
								String authType)
						{
						}

						public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
								String authType)
						{
						}
					} };

			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());

			javax.net.ssl.HostnameVerifier allHostsValid = new javax.net.ssl.HostnameVerifier()
			{
				public boolean verify(String hostname, javax.net.ssl.SSLSession session)
				{
					return true;
				}
			};

			httpRequest.setSSLSocketFactory(sc.getSocketFactory());
			httpRequest.setHostnameVerifier(allHostsValid);
		} catch (Exception ignored)
		{
			// If configuring insecure TLS fails, fall back to defaults.
		}
	}


	public static class OAuthForm
	{
		private String authorizationEndpoint;
		private String tokenEndpoint;
		private String clientId;
		private boolean usePkce;
		private String scope;
		private String extraParam1;

		public String authorizationEndpoint()
		{
			return authorizationEndpoint;
		}

		public void setAuthorizationEndpoint(String authorizationEndpoint)
		{
			this.authorizationEndpoint = authorizationEndpoint;
		}

		public String tokenEndpoint()
		{
			return tokenEndpoint;
		}

		public void setTokenEndpoint(String tokenEndpoint)
		{
			this.tokenEndpoint = tokenEndpoint;
		}

		public String clientId()
		{
			return clientId;
		}

		public void setClientId(String clientId)
		{
			this.clientId = clientId;
		}

		public boolean usePkce()
		{
			return usePkce;
		}

		public void setUsePkce(boolean usePkce)
		{
			this.usePkce = usePkce;
		}

		public String scope()
		{
			return scope;
		}

		public void setScope(String scope)
		{
			this.scope = scope;
		}

		public void setExtraParam1(String extraParam1)
		{
			this.extraParam1 = extraParam1;
		}
	}
}
