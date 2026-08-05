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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;

import ch.qos.logback.classic.Logger;
import io.imunity.oauthsampleclient.dpop.DPoPKeyType;
import io.imunity.oauthsampleclient.dpop.DPoPProofSigner;
import io.imunity.oauthsampleclient.dpop.DPoPRequestSender;
import io.imunity.oauthsampleclient.dpop.DPoPSummary;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class OAuthController
{
	private static final Logger log = (Logger) org.slf4j.LoggerFactory.getLogger(OAuthController.class);
	private static final ObjectMapper JSON = new ObjectMapper();
	private static final ObjectWriter PRETTY = JSON.writerWithDefaultPrettyPrinter();
	public static final String SESSION_STATE = "oauth_state";

	@GetMapping("/")
	public String index(HttpServletRequest request, Model model)
	{
		model.addAttribute("form", new OAuthForm());
		model.addAttribute("redirectUri", computeRedirectUri(request));
		model.addAttribute("dpopKeyTypes", DPoPKeyType.values());
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

		// The DPoP proof-of-possession key is generated on demand, per authentication attempt
		DPoPProofSigner dpopSigner = form.isUseDpop() ? DPoPProofSigner.withFreshKey(form.getDpopKeyType()) : null;

		// Store context in session
		OAuthState oauthState = new OAuthState(
				state.getValue(),
				codeVerifier != null ? codeVerifier.getValue() : null,
				form.tokenEndpoint(),
				form.getUserInfoEndpoint(),
				form.clientId(),
				form.getClientCred(),
				form.usePkce(),
				form.isUseAuthn(),
				dpopSigner != null ? dpopSigner.keyType() : null,
				dpopSigner != null ? dpopSigner.keyPairJson() : null,
				dpopSigner != null && form.isSendDpopJkt()
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
		if (oauthState.sendDpopJkt)
		{
			// RFC 9449 sec. 10: bind the authorization code to the DPoP key already at the authz request
			builder.dPoPJWKThumbprintConfirmation(dpopSigner.thumbprintConfirmation());
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
		if (oauthState == null)
		{
			model.addAttribute("rawResponse", "No authentication in progress in this session - start over.");
			return "result";
		}
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

		DPoPProofSigner dpopSigner = oauthState.dpopKeyType != null
				? DPoPProofSigner.withStoredKey(oauthState.dpopKeyType, oauthState.dpopKeyJson)
				: null;
		DPoPSummary dpopSummary = describeKey(dpopSigner, oauthState.sendDpopJkt);
		model.addAttribute("dpop", dpopSummary);

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

		URI tokenEndpoint = new URI(oauthState.tokenEndpoint);
		final com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = buildTokenRequest(oauthState, tokenEndpoint, grant);

		DPoPRequestSender.Outcome tokenOutcome;
		try
		{
			tokenOutcome = DPoPRequestSender.send(() -> prepare(tokenRequest.toHTTPRequest()), dpopSigner,
					"POST", tokenEndpoint, null);
		} catch (Exception e)
		{
			log.error("Error sending token request", e);
			model.addAttribute("rawResponse", "Error sending token request: " + e.getMessage());
			return "result";
		}
		dpopSummary.setTokenEndpointNonceChallenged(tokenOutcome.nonceChallenged());
		dpopSummary.setTokenEndpointNonce(valueOrNull(tokenOutcome.nonceUsed()));
		dpopSummary.setTokenEndpointProof(describeProof(tokenOutcome.proof()));

		HTTPResponse httpResponse = tokenOutcome.response();
		String body = httpResponse.getBody();
		model.addAttribute("rawResponse", "HTTP " + httpResponse.getStatusCode() + "\n\n" + body);

		Tokens tokens = null;
		try
		{
			TokenResponse tr = OIDCTokenResponse.parse(httpResponse);
			if (tr.indicatesSuccess())
			{
				AccessTokenResponse successResponse = tr.toSuccessResponse();
				model.addAttribute("parsedResponse",
						PRETTY.writeValueAsString(successResponse.toJSONObject()));

				tokens = successResponse.getTokens();
				if (tokens.getAccessToken() != null)
				{
					dpopSummary.setTokenTypeReturned(tokens.getAccessToken().getType().getValue());
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

		if (tokens != null && tokens.getAccessToken() != null && StringUtils.hasText(oauthState.userInfoEndpoint))
		{
			retrieveUserInfo(oauthState, tokens.getAccessToken(), dpopSigner, dpopSummary, model);
		}

		return "result";
	}

	private void retrieveUserInfo(OAuthState oauthState, AccessToken accessToken, DPoPProofSigner dpopSigner,
			DPoPSummary dpopSummary, Model model)
	{
		try
		{
			URI userInfoEndpoint = new URI(oauthState.userInfoEndpoint);
			dpopSummary.setUserInfoRequested(true);
			// The token must be presented the way the AS bound it: a proof only makes sense for a token
			// which the AS actually returned as DPoP bound
			boolean dpopBound = dpopSigner != null && AccessTokenType.DPOP.equals(accessToken.getType());
			AccessToken presentedToken = dpopBound
					? new DPoPAccessToken(accessToken.getValue())
					: new BearerAccessToken(accessToken.getValue());
			DPoPProofSigner userInfoSigner = dpopBound ? dpopSigner : null;
			dpopSummary.setUserInfoDpopBound(dpopBound);
			UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpoint, HTTPRequest.Method.GET,
					presentedToken);

			DPoPRequestSender.Outcome outcome = DPoPRequestSender.send(
					() -> prepare(userInfoRequest.toHTTPRequest()), userInfoSigner, "GET", userInfoEndpoint,
					presentedToken);

			dpopSummary.setUserInfoNonceChallenged(outcome.nonceChallenged());
			dpopSummary.setUserInfoNonce(valueOrNull(outcome.nonceUsed()));
			dpopSummary.setUserInfoProof(describeProof(outcome.proof()));

			HTTPResponse response = outcome.response();
			model.addAttribute("userInfoResponse",
					"HTTP " + response.getStatusCode() + "\n\n" + prettyJsonOrRaw(response.getBody()));
		} catch (Exception e)
		{
			log.error("Error retrieving user info", e);
			model.addAttribute("userInfoResponse", "Error retrieving user info: " + e.getMessage());
		}
	}

	private com.nimbusds.oauth2.sdk.TokenRequest buildTokenRequest(OAuthState oauthState, URI tokenEndpoint,
			AuthorizationCodeGrant grant)
	{
		if (oauthState.useAuthn)
		{
			return new com.nimbusds.oauth2.sdk.TokenRequest(
					tokenEndpoint,
					new ClientSecretBasic(new ClientID(oauthState.clientId),
							new Secret(oauthState.clientCred)),
					grant,
					null);
		}
		return new com.nimbusds.oauth2.sdk.TokenRequest(
				tokenEndpoint,
				new ClientID(oauthState.clientId),
				grant,
				null);
	}

	private DPoPSummary describeKey(DPoPProofSigner dpopSigner, boolean sendDpopJkt) throws Exception
	{
		DPoPSummary summary = new DPoPSummary();
		summary.setUsed(dpopSigner != null);
		if (dpopSigner == null)
			return summary;
		summary.setKeyType(dpopSigner.keyType().getLabel());
		summary.setJwsAlgorithm(dpopSigner.keyType().getJwsAlgorithm().getName());
		summary.setThumbprint(dpopSigner.thumbprintConfirmation().getValue().toString());
		summary.setPublicJwk(PRETTY.writeValueAsString(dpopSigner.publicKey().toJSONObject()));
		summary.setAuthorizationRequestJktSent(sendDpopJkt);
		return summary;
	}

	private static String describeProof(SignedJWT proof) throws Exception
	{
		if (proof == null)
			return null;
		return String.format("header: %s\n\nbody: %s",
				PRETTY.writeValueAsString(proof.getHeader().toJSONObject()),
				PRETTY.writeValueAsString(proof.getJWTClaimsSet().toJSONObject()));
	}

	private static String valueOrNull(com.nimbusds.openid.connect.sdk.Nonce nonce)
	{
		return nonce != null ? nonce.getValue() : null;
	}

	private static String prettyJsonOrRaw(String body)
	{
		if (!StringUtils.hasText(body))
			return body;
		try
		{
			return PRETTY.writeValueAsString(JSON.readTree(body));
		} catch (Exception e)
		{
			return body;
		}
	}

	private static HTTPRequest prepare(HTTPRequest httpRequest)
	{
		configureInsecureTLS(httpRequest);
		return httpRequest;
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
			String userInfoEndpoint,
			String clientId,
			String clientCred,
			boolean usePKCE,
			boolean useAuthn,
			DPoPKeyType dpopKeyType,
			String dpopKeyJson,
			boolean sendDpopJkt)
	{
	}


	public static class OAuthForm
	{
		private String authorizationEndpoint;
		private String tokenEndpoint;
		private String userInfoEndpoint;
		private String clientId;
		private String clientCred;
		private boolean usePkce;
		private boolean useAuthn;
		private boolean useDpop;
		private DPoPKeyType dpopKeyType = DPoPKeyType.EC;
		private boolean sendDpopJkt;
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

		public String getUserInfoEndpoint()
		{
			return userInfoEndpoint;
		}

		public void setUserInfoEndpoint(String userInfoEndpoint)
		{
			this.userInfoEndpoint = userInfoEndpoint;
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

		public boolean isUseDpop()
		{
			return useDpop;
		}

		public void setUseDpop(boolean useDpop)
		{
			this.useDpop = useDpop;
		}

		public DPoPKeyType getDpopKeyType()
		{
			return dpopKeyType != null ? dpopKeyType : DPoPKeyType.EC;
		}

		public void setDpopKeyType(DPoPKeyType dpopKeyType)
		{
			this.dpopKeyType = dpopKeyType;
		}

		public boolean isSendDpopJkt()
		{
			return sendDpopJkt;
		}

		public void setSendDpopJkt(boolean sendDpopJkt)
		{
			this.sendDpopJkt = sendDpopJkt;
		}
	}
}
