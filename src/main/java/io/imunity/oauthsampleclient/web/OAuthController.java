package io.imunity.oauthsampleclient.web;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationRequest;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationResponse;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.device.DeviceCode;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
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
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;

import ch.qos.logback.classic.Logger;
import io.imunity.oauthsampleclient.config.ClientDefaults;
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
	static final String DEVICE_SESSION_STATE = "device_oauth_state";
	private static final long MIN_POLLING_INTERVAL_SECONDS = 1;
	private static final long MAX_POLLING_INTERVAL_SECONDS = 3600;

	private final ClientDefaults defaults;
	private final Clock clock;

	@Autowired
	OAuthController(ClientDefaults defaults)
	{
		this(defaults, Clock.systemUTC());
	}

	OAuthController(ClientDefaults defaults, Clock clock)
	{
		this.defaults = defaults;
		this.clock = clock;
	}

	/**
	 * Query parameters of the start screen URL override the configured defaults, field by field, so that a
	 * filled in form can be shared as a link or bookmarked. A parameter which is absent leaves the default
	 * in place, and one which can not be converted (a stale enum constant, a non numeric interval) is
	 * ignored rather than rejected - a mangled link still opens a usable form.
	 * <p>
	 * The binding is deliberately local to this method instead of a {@code @ModelAttribute} factory: such a
	 * factory would also pre-fill the form bound in the POST handlers, where an unchecked checkbox is simply
	 * absent from the request, and clearing an option enabled by default would stop taking effect.
	 */
	@GetMapping("/")
	public String index(HttpServletRequest request, Model model)
	{
		OAuthForm form = OAuthForm.withDefaults(defaults);
		// bind() records conversion failures in its own BindingResult; only validate()/close() would throw
		new ServletRequestDataBinder(form, "form").bind(request);
		model.addAttribute("form", form);
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

		if (form.isUsePkce())
		{
			codeVerifier = new CodeVerifier();
		}

		// The DPoP proof-of-possession key is generated on demand, per authentication attempt
		DPoPProofSigner dpopSigner = form.isUseDpop() ? DPoPProofSigner.withFreshKey(form.getDpopKeyType()) : null;

		// Store context in session
		OAuthState oauthState = new OAuthState(
				state.getValue(),
				codeVerifier != null ? codeVerifier.getValue() : null,
				form.getTokenEndpoint(),
				form.getUserInfoEndpoint(),
				form.getClientId(),
				form.getClientCred(),
				form.isUsePkce(),
				form.isUseAuthn(),
				dpopSigner != null ? dpopSigner.keyType() : null,
				dpopSigner != null ? dpopSigner.keyPairJson() : null,
				dpopSigner != null && form.isSendDpopJkt()
				);
		session.setAttribute(SESSION_STATE, oauthState);

		URI authzEndpoint = new URI(form.getAuthorizationEndpoint());
		AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(new ResponseType("code"),
				new ClientID(form.getClientId()))
					.redirectionURI(new URI(redirectUri))
					.state(state);

		if (StringUtils.hasText(form.getScope()))
		{
			builder.scope(Scope.parse(form.getScope()));
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
		ExtraParameter extraParameter = parseExtraParameter(form.getExtraParam1());
		if (extraParameter != null)
			builder.customParameter(extraParameter.name(), extraParameter.value());

		AuthorizationRequest authRequest = builder.endpointURI(authzEndpoint).build();
		String redirect = authRequest.toURI().toString();
		return "redirect:" + redirect;
	}

	@PostMapping("/device/start")
	public String startDeviceAuth(@ModelAttribute("form") OAuthForm form, HttpSession session, Model model)
	{
		session.removeAttribute(DEVICE_SESSION_STATE);
		if (!StringUtils.hasText(form.getDeviceAuthorizationEndpoint()))
			return renderDeviceStartError(model, "The device authorization endpoint URL is required.");
		if (form.getDevicePollingIntervalSeconds() < MIN_POLLING_INTERVAL_SECONDS
				|| form.getDevicePollingIntervalSeconds() > MAX_POLLING_INTERVAL_SECONDS)
		{
			return renderDeviceStartError(model, "The polling interval must be between "
					+ MIN_POLLING_INTERVAL_SECONDS + " and " + MAX_POLLING_INTERVAL_SECONDS + " seconds.");
		}

		DPoPProofSigner dpopSigner;
		try
		{
			dpopSigner = form.isUseDpop() ? DPoPProofSigner.withFreshKey(form.getDpopKeyType()) : null;
		} catch (Exception e)
		{
			log.error("Error generating the DPoP key", e);
			return renderDeviceStartError(model, "Error generating the DPoP key: " + e.getMessage());
		}

		try
		{
			URI deviceAuthorizationEndpoint = new URI(form.getDeviceAuthorizationEndpoint());
			DeviceAuthorizationRequest.Builder builder = form.isUseAuthn()
					? new DeviceAuthorizationRequest.Builder(new ClientSecretBasic(
							new ClientID(form.getClientId()), new Secret(form.getClientCred())))
					: new DeviceAuthorizationRequest.Builder(new ClientID(form.getClientId()));
			builder.endpointURI(deviceAuthorizationEndpoint);
			if (StringUtils.hasText(form.getScope()))
				builder.scope(Scope.parse(form.getScope()));
			ExtraParameter extraParameter = parseExtraParameter(form.getExtraParam1());
			if (extraParameter != null)
				builder.customParameter(extraParameter.name(), extraParameter.value());
			HTTPResponse httpResponse = prepare(builder.build().toHTTPRequest()).send();
			String rawResponse = formatRawResponse(httpResponse);
			model.addAttribute("deviceRawResponse", rawResponse);

			DeviceAuthorizationResponse response = DeviceAuthorizationResponse.parse(httpResponse);
			if (!response.indicatesSuccess())
			{
				model.addAttribute("deviceError",
						PRETTY.writeValueAsString(response.toErrorResponse().toJSONObject()));
				return "device";
			}

			DeviceAuthorizationSuccessResponse success = response.toSuccessResponse();
			long effectiveInterval = Math.max(form.getDevicePollingIntervalSeconds(), success.getInterval());
			Instant now = clock.instant();
			OAuthState oauthState = oauthStateFor(form, dpopSigner);
			DeviceOAuthState deviceState = new DeviceOAuthState(
					oauthState,
					success.getDeviceCode().getValue(),
					success.getUserCode().getValue(),
					success.getVerificationURI().toString(),
					success.getVerificationURIComplete() != null
							? success.getVerificationURIComplete().toString() : null,
					success.getLifetime(),
					form.getDevicePollingIntervalSeconds(),
					success.getInterval(),
					effectiveInterval,
					now.plusSeconds(success.getLifetime()),
					now.plusSeconds(effectiveInterval),
					rawResponse,
					null,
					null,
					false);
			session.setAttribute(DEVICE_SESSION_STATE, deviceState);
			populateDeviceModel(model, deviceState, effectiveInterval);
			return "device";
		} catch (Exception e)
		{
			log.error("Error sending device authorization request", e);
			return renderDeviceStartError(model, "Error sending device authorization request: " + e.getMessage());
		}
	}

	@PostMapping("/device/poll")
	public String pollDeviceToken(HttpSession session, Model model)
	{
		DeviceOAuthState deviceState = (DeviceOAuthState) session.getAttribute(DEVICE_SESSION_STATE);
		if (deviceState == null)
		{
			model.addAttribute("rawResponse", "No device authorization is in progress in this session - start over.");
			return "result";
		}

		Instant now = clock.instant();
		if (!now.isBefore(deviceState.expiresAt()))
		{
			session.removeAttribute(DEVICE_SESSION_STATE);
			model.addAttribute("rawResponse", "The device code expired before authorization completed.");
			model.addAttribute("oauthError", "{\"error\":\"expired_token\"}");
			return "result";
		}
		if (now.isBefore(deviceState.nextPollAt()))
		{
			long delay = secondsUntil(now, deviceState.nextPollAt());
			model.addAttribute("pollStatus", "The next token request is rate-limited; waiting before polling.");
			populateDeviceModel(model, deviceState, delay);
			return "device";
		}

		OAuthState oauthState = deviceState.oauthState();
		DPoPProofSigner dpopSigner;
		DPoPSummary dpopSummary;
		try
		{
			dpopSigner = signerFrom(oauthState);
			dpopSummary = describeKey(dpopSigner, oauthState.sendDpopJkt);
			model.addAttribute("dpop", dpopSummary);
		} catch (Exception e)
		{
			session.removeAttribute(DEVICE_SESSION_STATE);
			model.addAttribute("rawResponse", "Error restoring the DPoP key: " + e.getMessage());
			return "result";
		}

		URI tokenEndpoint;
		DPoPRequestSender.Outcome tokenOutcome;
		try
		{
			tokenEndpoint = new URI(oauthState.tokenEndpoint);
			DeviceCodeGrant grant = new DeviceCodeGrant(new DeviceCode(deviceState.deviceCode()));
			com.nimbusds.oauth2.sdk.TokenRequest tokenRequest = buildTokenRequest(oauthState, tokenEndpoint, grant);
			Nonce priorNonce = StringUtils.hasText(deviceState.tokenEndpointNonce())
					? new Nonce(deviceState.tokenEndpointNonce()) : null;
			tokenOutcome = DPoPRequestSender.send(() -> prepare(tokenRequest.toHTTPRequest()), dpopSigner,
					"POST", tokenEndpoint, null, priorNonce);
		} catch (Exception e)
		{
			log.error("Error sending device token request", e);
			session.removeAttribute(DEVICE_SESSION_STATE);
			model.addAttribute("rawResponse", "Error sending token request: " + e.getMessage());
			return "result";
		}

		String nextNonce = tokenOutcome.serverNonce() != null ? tokenOutcome.serverNonce().getValue()
				: deviceState.tokenEndpointNonce();
		boolean nonceChallenged = deviceState.tokenEndpointNonceChallenged() || tokenOutcome.nonceChallenged();
		TokenResponse tokenResponse;
		try
		{
			tokenResponse = parseTokenResponse(tokenOutcome.response());
		} catch (Exception e)
		{
			session.removeAttribute(DEVICE_SESSION_STATE);
			applyTokenOutcomeSummary(dpopSummary, tokenOutcome, nonceChallenged);
			renderTokenResponse(oauthState, dpopSigner, dpopSummary, tokenOutcome.response(), model);
			model.addAttribute("oauthError", "Unable to parse token response: " + e.getMessage());
			return "result";
		}

		if (!tokenResponse.indicatesSuccess())
		{
			String errorCode = tokenResponse.toErrorResponse().getErrorObject().getCode();
			if ("authorization_pending".equals(errorCode) || "slow_down".equals(errorCode))
			{
				long nextInterval = deviceState.pollingIntervalSeconds();
				String status = "Authorization is still pending.";
				if ("slow_down".equals(errorCode))
				{
					nextInterval = Math.min(MAX_POLLING_INTERVAL_SECONDS, nextInterval + 5);
					status = "The authorization server asked the client to slow down; the polling interval was increased.";
				}
				DeviceOAuthState nextState = deviceState.afterPoll(nextInterval,
						now.plusSeconds(nextInterval), formatRawResponse(tokenOutcome.response()), nextNonce,
						nonceChallenged);
				session.setAttribute(DEVICE_SESSION_STATE, nextState);
				model.addAttribute("pollStatus", status);
				populateDeviceModel(model, nextState, nextInterval);
				return "device";
			}
		}

		session.removeAttribute(DEVICE_SESSION_STATE);
		applyTokenOutcomeSummary(dpopSummary, tokenOutcome, nonceChallenged);
		renderTokenResponse(oauthState, dpopSigner, dpopSummary, tokenOutcome.response(), model);
		return "result";
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
		applyTokenOutcomeSummary(dpopSummary, tokenOutcome, tokenOutcome.nonceChallenged());
		renderTokenResponse(oauthState, dpopSigner, dpopSummary, tokenOutcome.response(), model);
		return "result";
	}

	private void renderTokenResponse(OAuthState oauthState, DPoPProofSigner dpopSigner, DPoPSummary dpopSummary,
			HTTPResponse httpResponse, Model model)
	{
		model.addAttribute("rawResponse", formatRawResponse(httpResponse));

		Tokens tokens = null;
		try
		{
			TokenResponse tr = parseTokenResponse(httpResponse);
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
	}

	private OAuthState oauthStateFor(OAuthForm form, DPoPProofSigner dpopSigner)
	{
		return new OAuthState(
				null,
				null,
				form.getTokenEndpoint(),
				form.getUserInfoEndpoint(),
				form.getClientId(),
				form.getClientCred(),
				false,
				form.isUseAuthn(),
				dpopSigner != null ? dpopSigner.keyType() : null,
				dpopSigner != null ? dpopSigner.keyPairJson() : null,
				false);
	}

	private DPoPProofSigner signerFrom(OAuthState oauthState) throws Exception
	{
		return oauthState.dpopKeyType != null
				? DPoPProofSigner.withStoredKey(oauthState.dpopKeyType, oauthState.dpopKeyJson)
				: null;
	}

	private void populateDeviceModel(Model model, DeviceOAuthState state, long pollDelaySeconds)
	{
		model.addAttribute("deviceAuthorizationSuccessful", true);
		model.addAttribute("userCode", state.userCode());
		model.addAttribute("verificationUri", state.verificationUri());
		model.addAttribute("verificationUriComplete", state.verificationUriComplete());
		model.addAttribute("deviceLifetimeSeconds", state.lifetimeSeconds());
		model.addAttribute("deviceExpiresInSeconds",
				Math.max(0, Duration.between(clock.instant(), state.expiresAt()).toSeconds()));
		model.addAttribute("configuredPollingIntervalSeconds", state.configuredPollingIntervalSeconds());
		model.addAttribute("serverPollingIntervalSeconds", state.serverPollingIntervalSeconds());
		model.addAttribute("pollingIntervalSeconds", state.pollingIntervalSeconds());
		model.addAttribute("pollDelaySeconds", Math.max(MIN_POLLING_INTERVAL_SECONDS, pollDelaySeconds));
		model.addAttribute("deviceRawResponse", state.deviceRawResponse());
		model.addAttribute("lastPollResponse", state.lastPollResponse());
	}

	private String renderDeviceStartError(Model model, String message)
	{
		model.addAttribute("deviceError", message);
		return "device";
	}

	private void applyTokenOutcomeSummary(DPoPSummary summary, DPoPRequestSender.Outcome outcome,
			boolean nonceChallenged)
	{
		summary.setTokenEndpointNonceChallenged(nonceChallenged);
		summary.setTokenEndpointNonce(valueOrNull(outcome.nonceUsed()));
		try
		{
			summary.setTokenEndpointProof(describeProof(outcome.proof()));
		} catch (Exception e)
		{
			log.error("Error rendering the DPoP proof", e);
		}
	}

	private static long secondsUntil(Instant from, Instant until)
	{
		long millis = Math.max(0, Duration.between(from, until).toMillis());
		return Math.max(MIN_POLLING_INTERVAL_SECONDS, (millis + 999) / 1000);
	}

	private static String formatRawResponse(HTTPResponse response)
	{
		return "HTTP " + response.getStatusCode() + "\n\n" + response.getBody();
	}

	private static TokenResponse parseTokenResponse(HTTPResponse response) throws Exception
	{
		return response.getStatusCode() >= 200 && response.getStatusCode() < 300
				? OIDCTokenResponse.parse(response)
				: TokenResponse.parse(response);
	}

	private static ExtraParameter parseExtraParameter(String value)
	{
		if (!StringUtils.hasText(value))
			return null;
		int separator = value.indexOf('=');
		if (separator <= 0)
			throw new IllegalArgumentException("Additional OAuth parameter must use the syntax name=value");
		return new ExtraParameter(value.substring(0, separator), value.substring(separator + 1));
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
			AuthorizationGrant grant)
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
		// A configured redirect URI wins over autodetection - and must be used consistently at both the
		// authorization and the token request, which it is, as both go through this method.
		if (StringUtils.hasText(defaults.getRedirectUri()))
			return defaults.getRedirectUri();

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

	private record DeviceOAuthState(
			OAuthState oauthState,
			String deviceCode,
			String userCode,
			String verificationUri,
			String verificationUriComplete,
			long lifetimeSeconds,
			long configuredPollingIntervalSeconds,
			long serverPollingIntervalSeconds,
			long pollingIntervalSeconds,
			Instant expiresAt,
			Instant nextPollAt,
			String deviceRawResponse,
			String lastPollResponse,
			String tokenEndpointNonce,
			boolean tokenEndpointNonceChallenged)
	{
		DeviceOAuthState afterPoll(long newPollingIntervalSeconds, Instant newNextPollAt,
				String newLastPollResponse, String newTokenEndpointNonce, boolean newNonceChallenged)
		{
			return new DeviceOAuthState(oauthState, deviceCode, userCode, verificationUri,
					verificationUriComplete, lifetimeSeconds, configuredPollingIntervalSeconds,
					serverPollingIntervalSeconds, newPollingIntervalSeconds, expiresAt, newNextPollAt,
					deviceRawResponse, newLastPollResponse, newTokenEndpointNonce, newNonceChallenged);
		}
	}

	private record ExtraParameter(String name, String value)
	{
	}


	public static class OAuthForm
	{
		private String authorizationEndpoint;
		private String deviceAuthorizationEndpoint;
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
		private long devicePollingIntervalSeconds = 5;

		static OAuthForm withDefaults(ClientDefaults defaults)
		{
			OAuthForm form = new OAuthForm();
			form.setAuthorizationEndpoint(defaults.getAuthorizationEndpoint());
			form.setDeviceAuthorizationEndpoint(defaults.getDeviceAuthorizationEndpoint());
			form.setTokenEndpoint(defaults.getTokenEndpoint());
			form.setUserInfoEndpoint(defaults.getUserInfoEndpoint());
			form.setClientId(defaults.getClientId());
			form.setClientCred(defaults.getClientCred());
			form.setScope(defaults.getScope());
			form.setExtraParam1(defaults.getExtraParam1());
			form.setUsePkce(defaults.isUsePkce());
			form.setUseAuthn(defaults.isUseAuthn());
			form.setUseDpop(defaults.isUseDpop());
			form.setDpopKeyType(defaults.getDpopKeyType());
			form.setSendDpopJkt(defaults.isSendDpopJkt());
			form.setDevicePollingIntervalSeconds(defaults.getDevicePollingIntervalSeconds());
			return form;
		}

		public String getAuthorizationEndpoint()
		{
			return authorizationEndpoint;
		}

		public void setAuthorizationEndpoint(String authorizationEndpoint)
		{
			this.authorizationEndpoint = authorizationEndpoint;
		}

		public String getDeviceAuthorizationEndpoint()
		{
			return deviceAuthorizationEndpoint;
		}

		public void setDeviceAuthorizationEndpoint(String deviceAuthorizationEndpoint)
		{
			this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
		}

		public String getTokenEndpoint()
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

		public String getClientId()
		{
			return clientId;
		}

		public void setClientId(String clientId)
		{
			this.clientId = clientId;
		}

		public boolean isUsePkce()
		{
			return usePkce;
		}

		public void setUsePkce(boolean usePkce)
		{
			this.usePkce = usePkce;
		}

		public String getScope()
		{
			return scope;
		}

		public void setScope(String scope)
		{
			this.scope = scope;
		}

		public String getExtraParam1()
		{
			return extraParam1;
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

		public long getDevicePollingIntervalSeconds()
		{
			return devicePollingIntervalSeconds;
		}

		public void setDevicePollingIntervalSeconds(long devicePollingIntervalSeconds)
		{
			this.devicePollingIntervalSeconds = devicePollingIntervalSeconds;
		}
	}
}
