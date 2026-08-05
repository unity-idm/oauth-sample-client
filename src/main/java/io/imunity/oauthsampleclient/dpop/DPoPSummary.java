package io.imunity.oauthsampleclient.dpop;

/**
 * What actually happened with DPoP during the flow, as presented on the result screen.
 */
public class DPoPSummary
{
	private boolean used;
	private String keyType;
	private String jwsAlgorithm;
	private String thumbprint;
	private String publicJwk;
	private boolean authorizationRequestJktSent;
	private String tokenTypeReturned;

	private boolean tokenEndpointNonceChallenged;
	private String tokenEndpointNonce;
	private String tokenEndpointProof;

	private boolean userInfoRequested;
	private boolean userInfoNonceChallenged;
	private String userInfoNonce;
	private String userInfoProof;
	private boolean userInfoDpopBound;

	public boolean isUsed()
	{
		return used;
	}

	public void setUsed(boolean used)
	{
		this.used = used;
	}

	public String getKeyType()
	{
		return keyType;
	}

	public void setKeyType(String keyType)
	{
		this.keyType = keyType;
	}

	public String getJwsAlgorithm()
	{
		return jwsAlgorithm;
	}

	public void setJwsAlgorithm(String jwsAlgorithm)
	{
		this.jwsAlgorithm = jwsAlgorithm;
	}

	public String getThumbprint()
	{
		return thumbprint;
	}

	public void setThumbprint(String thumbprint)
	{
		this.thumbprint = thumbprint;
	}

	public String getPublicJwk()
	{
		return publicJwk;
	}

	public void setPublicJwk(String publicJwk)
	{
		this.publicJwk = publicJwk;
	}

	public boolean isAuthorizationRequestJktSent()
	{
		return authorizationRequestJktSent;
	}

	public void setAuthorizationRequestJktSent(boolean authorizationRequestJktSent)
	{
		this.authorizationRequestJktSent = authorizationRequestJktSent;
	}

	public String getTokenTypeReturned()
	{
		return tokenTypeReturned;
	}

	public void setTokenTypeReturned(String tokenTypeReturned)
	{
		this.tokenTypeReturned = tokenTypeReturned;
	}

	public boolean isTokenEndpointNonceChallenged()
	{
		return tokenEndpointNonceChallenged;
	}

	public void setTokenEndpointNonceChallenged(boolean tokenEndpointNonceChallenged)
	{
		this.tokenEndpointNonceChallenged = tokenEndpointNonceChallenged;
	}

	public String getTokenEndpointNonce()
	{
		return tokenEndpointNonce;
	}

	public void setTokenEndpointNonce(String tokenEndpointNonce)
	{
		this.tokenEndpointNonce = tokenEndpointNonce;
	}

	public String getTokenEndpointProof()
	{
		return tokenEndpointProof;
	}

	public void setTokenEndpointProof(String tokenEndpointProof)
	{
		this.tokenEndpointProof = tokenEndpointProof;
	}

	public boolean isUserInfoRequested()
	{
		return userInfoRequested;
	}

	public void setUserInfoRequested(boolean userInfoRequested)
	{
		this.userInfoRequested = userInfoRequested;
	}

	public boolean isUserInfoNonceChallenged()
	{
		return userInfoNonceChallenged;
	}

	public void setUserInfoNonceChallenged(boolean userInfoNonceChallenged)
	{
		this.userInfoNonceChallenged = userInfoNonceChallenged;
	}

	public String getUserInfoNonce()
	{
		return userInfoNonce;
	}

	public void setUserInfoNonce(String userInfoNonce)
	{
		this.userInfoNonce = userInfoNonce;
	}

	public String getUserInfoProof()
	{
		return userInfoProof;
	}

	public void setUserInfoProof(String userInfoProof)
	{
		this.userInfoProof = userInfoProof;
	}

	public void setUserInfoDpopBound(boolean userInfoDpopBound)
	{
		this.userInfoDpopBound = userInfoDpopBound;
	}

	/** How the access token was presented to the UserInfo endpoint, null when it was not called at all. */
	public String getUserInfoTokenPresentation()
	{
		if (!userInfoRequested)
			return null;
		if (userInfoDpopBound)
			return "DPoP scheme, with a proof bound to the access token (ath)";
		if (used)
			return "Bearer scheme, without a proof - the AS did not return a DPoP bound access token";
		return "Bearer scheme";
	}

	public String getHeadline()
	{
		if (!used)
			return "DPoP was NOT used - plain bearer tokens";
		if (tokenEndpointNonceChallenged || userInfoNonceChallenged)
			return "DPoP was used, WITH a server provided nonce";
		return "DPoP was used, WITHOUT a server provided nonce";
	}

	public String getTokenEndpointNonceStatus()
	{
		return nonceStatus(true, tokenEndpointNonceChallenged, tokenEndpointNonce);
	}

	public String getUserInfoNonceStatus()
	{
		if (used && userInfoRequested && !userInfoDpopBound)
			return "n/a - the access token was not DPoP bound, so no proof was sent";
		return nonceStatus(userInfoRequested, userInfoNonceChallenged, userInfoNonce);
	}

	private String nonceStatus(boolean proofSent, boolean challenged, String nonce)
	{
		if (!used)
			return "n/a - DPoP not used";
		if (!proofSent)
			return "n/a - endpoint not called";
		if (!challenged)
			return "Not required by the server - proof sent without a nonce";
		return "Required by the server - request retried with nonce: " + nonce;
	}
}
