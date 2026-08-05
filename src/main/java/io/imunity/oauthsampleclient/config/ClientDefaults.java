package io.imunity.oauthsampleclient.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import io.imunity.oauthsampleclient.dpop.DPoPKeyType;

/**
 * Values pre-filled into the form on the start screen, so that a frequently used AS does not have to be typed
 * in over and over again. All of them are only defaults - each one can still be changed in the UI before the
 * flow is started.
 * <p>
 * Bound from {@code oauth.client.defaults.*}. The shipped values are in {@code application.properties}; they
 * can be overridden locally in {@code client-defaults.properties} (git ignored, see
 * {@code client-defaults.properties.example}).
 */
@ConfigurationProperties(prefix = "oauth.client.defaults")
public class ClientDefaults
{
	private String authorizationEndpoint;
	private String tokenEndpoint;
	private String userInfoEndpoint;
	private String clientId;
	private String clientCred;
	private String scope;
	private String extraParam1;
	private boolean usePkce;
	private boolean useAuthn;
	private boolean useDpop;
	private DPoPKeyType dpopKeyType = DPoPKeyType.EC;
	private boolean sendDpopJkt;

	/**
	 * Redirect URI advertised to the AS. Empty (the default) means it is computed from the incoming request,
	 * honoring the {@code X-Forwarded-Proto} and {@code X-Forwarded-Host} headers. Set it only when that
	 * autodetection can not work, e.g. behind a proxy which does not send those headers.
	 */
	private String redirectUri;

	public String getAuthorizationEndpoint()
	{
		return authorizationEndpoint;
	}

	public void setAuthorizationEndpoint(String authorizationEndpoint)
	{
		this.authorizationEndpoint = authorizationEndpoint;
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

	public String getClientCred()
	{
		return clientCred;
	}

	public void setClientCred(String clientCred)
	{
		this.clientCred = clientCred;
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

	public boolean isUsePkce()
	{
		return usePkce;
	}

	public void setUsePkce(boolean usePkce)
	{
		this.usePkce = usePkce;
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

	public String getRedirectUri()
	{
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri)
	{
		this.redirectUri = redirectUri;
	}
}
