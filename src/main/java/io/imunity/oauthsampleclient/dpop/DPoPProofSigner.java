package io.imunity.oauthsampleclient.dpop;

import java.net.URI;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.URIUtils;
import com.nimbusds.openid.connect.sdk.Nonce;

/**
 * Holds the ephemeral DPoP proof-of-possession key of a single authentication attempt and issues DPoP proofs
 * with it. The key is generated on demand, kept only for the duration of the flow and serialized into the HTTP
 * session between the authorization request and the callback.
 */
public class DPoPProofSigner
{
	private final DPoPKeyType keyType;
	private final JWK keyPair;
	private final DPoPProofFactory proofFactory;

	private DPoPProofSigner(DPoPKeyType keyType, JWK keyPair) throws JOSEException
	{
		this.keyType = keyType;
		this.keyPair = keyPair;
		this.proofFactory = new DefaultDPoPProofFactory(keyPair, keyType.getJwsAlgorithm());
	}

	public static DPoPProofSigner withFreshKey(DPoPKeyType keyType) throws JOSEException
	{
		return new DPoPProofSigner(keyType, keyType.generateKey());
	}

	public static DPoPProofSigner withStoredKey(DPoPKeyType keyType, String keyPairJson)
			throws JOSEException, ParseException
	{
		try
		{
			return new DPoPProofSigner(keyType, JWK.parse(keyPairJson));
		} catch (java.text.ParseException e)
		{
			throw new ParseException("Cannot parse the stored DPoP key: " + e.getMessage(), e);
		}
	}

	/**
	 * Creates a DPoP proof for a request. Both the access token (source of the {@code ath} claim) and the
	 * server provided nonce are optional.
	 */
	public SignedJWT createProof(String httpMethod, URI endpoint, AccessToken accessToken, Nonce nonce)
			throws JOSEException
	{
		// htu must carry neither a query nor a fragment
		return proofFactory.createDPoPJWT(httpMethod, URIUtils.getBaseURI(endpoint), accessToken, nonce);
	}

	public JWKThumbprintConfirmation thumbprintConfirmation() throws JOSEException
	{
		return JWKThumbprintConfirmation.of(keyPair);
	}

	public String keyPairJson()
	{
		return keyPair.toJSONString();
	}

	public JWK publicKey()
	{
		return keyPair.toPublicJWK();
	}

	public DPoPKeyType keyType()
	{
		return keyType;
	}
}
