package io.imunity.oauthsampleclient.web;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import ch.qos.logback.classic.Logger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class OAuthController
{
	private static final Logger log = (Logger) org.slf4j.LoggerFactory.getLogger(OAuthController.class);
	private static final ObjectWriter PRETTY = new ObjectMapper().writerWithDefaultPrettyPrinter();
	public static final String SESSION_STATE = "oauth_state";

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
		OAuthState oauthState = new OAuthState(
				state.getValue(),
				codeVerifier != null ? codeVerifier.getValue() : null,
				form.tokenEndpoint(),
				form.clientId(),
				form.getClientCred(),
				form.usePkce(),
				form.isUseAuthn()
				);
		session.setAttribute(SESSION_STATE, oauthState);

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
		OAuthState oauthState = (OAuthState) session.getAttribute(SESSION_STATE);
		if (!StringUtils.hasText(oauthState.state) || !Objects.equals(oauthState.state, stateParam))
		{
			model.addAttribute("rawResponse", "State mismatch or missing session. Expected: " + oauthState.state
					+ ", got: " + stateParam);
			return "result";
		}
		if (StringUtils.hasText(error))
		{
			model.addAttribute("rawResponse", "Error returned from authorization endpoint: " + error + " - "
					+ errorDescription);
			return "result";
		}

		String redirectUri = computeRedirectUri(request);

		AuthorizationCodeGrant grant;
		if (oauthState.usePKCE)
		{
			grant = new AuthorizationCodeGrant(new AuthorizationCode(code), new URI(redirectUri),
					new CodeVerifier(oauthState.codeVerifier));
		} else
		{
			grant = new AuthorizationCodeGrant(new AuthorizationCode(code), new URI(redirectUri));
		}
		com.nimbusds.oauth2.sdk.TokenRequest tokenRequest;
		if (oauthState.useAuthn)
		{
			tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(
					new URI(oauthState.tokenEndpoint),
					new ClientSecretBasic(new ClientID(oauthState.clientId),
							new Secret(oauthState.clientCred)),
					grant,
					null);
		} else
		{
			tokenRequest = new com.nimbusds.oauth2.sdk.TokenRequest(
					new URI(oauthState.tokenEndpoint),
					new ClientID(oauthState.clientId),
					grant,
					null);
		}
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
				model.addAttribute("parsedResponse",
						PRETTY.writeValueAsString(successResponse.toJSONObject()));

				Tokens tokens = successResponse.getTokens();
				if (tokens.getAccessToken() != null)
				{
					try
					{
						SignedJWT accessToken = SignedJWT.parse(
								tokens.getAccessToken().getValue());
						String stringRep = String.format("header: %s\n\nbody: %s",
								PRETTY.writeValueAsString(accessToken.getHeader().toJSONObject()),
								PRETTY.writeValueAsString(accessToken.getJWTClaimsSet().toJSONObject()));
						model.addAttribute("accessToken", stringRep);
					} catch (Exception e)
					{
						model.addAttribute("accessToken", tokens.getAccessToken().getValue());
					}
				}

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

	private record OAuthState(
			String state,
			String codeVerifier,
			String tokenEndpoint,
			String clientId,
			String clientCred,
			boolean usePKCE,
			boolean useAuthn)
	{
	}


	public static class OAuthForm
	{
		private String authorizationEndpoint;
		private String tokenEndpoint;
		private String clientId;
		private String clientCred;
		private boolean usePkce;
		private boolean useAuthn;
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

		public String getClientCred()
		{
			return clientCred;
		}

		public void setClientCred(String clientCred)
		{
			this.clientCred = clientCred;
		}

		public boolean isUseAuthn()
		{
			return useAuthn;
		}

		public void setUseAuthn(boolean useAuthn)
		{
			this.useAuthn = useAuthn;
		}
	}
}
