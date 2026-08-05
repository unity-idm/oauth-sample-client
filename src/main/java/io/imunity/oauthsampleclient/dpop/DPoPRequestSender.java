package io.imunity.oauthsampleclient.dpop;

import java.net.URI;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;

/**
 * Sends an HTTP request with a DPoP proof attached, transparently handling the server provided nonce dance of
 * RFC 9449: a server which requires a nonce rejects the first, nonce-less request with a {@code use_dpop_nonce}
 * error and returns the nonce to use in the {@code DPoP-Nonce} header. The request is then retried once, with
 * a freshly signed proof carrying that nonce.
 */
public class DPoPRequestSender
{
	private static final String USE_DPOP_NONCE = "use_dpop_nonce";

	@FunctionalInterface
	public interface RequestSupplier
	{
		/**
		 * Builds a fresh, ready to send request. Called again for the nonce retry, as a request may only
		 * be sent once.
		 */
		HTTPRequest get() throws Exception;
	}

	/**
	 * Outcome of a (possibly retried) request.
	 *
	 * @param response the final HTTP response
	 * @param proof the DPoP proof of the final attempt, null if DPoP was not used
	 * @param nonceUsed the server nonce included in the final proof, null if none was needed
	 * @param nonceChallenged whether the server explicitly asked for a nonce with a {@code use_dpop_nonce}
	 *            error
	 * @param serverNonce the last nonce received from the server, also when it was merely offered for
	 *            subsequent requests
	 */
	public record Outcome(
			HTTPResponse response,
			SignedJWT proof,
			Nonce nonceUsed,
			boolean nonceChallenged,
			Nonce serverNonce)
	{
	}

	public static Outcome send(RequestSupplier requestSupplier, DPoPProofSigner signer, String httpMethod,
			URI endpoint, AccessToken accessToken) throws Exception
	{
		if (signer == null)
		{
			HTTPResponse response = requestSupplier.get().send();
			return new Outcome(response, null, null, false, response.getDPoPNonce());
		}

		SignedJWT proof = signer.createProof(httpMethod, endpoint, accessToken, null);
		HTTPResponse response = sendWithProof(requestSupplier, proof);
		Nonce serverNonce = response.getDPoPNonce();

		if (!requiresNonce(response))
			return new Outcome(response, proof, null, false, serverNonce);

		proof = signer.createProof(httpMethod, endpoint, accessToken, serverNonce);
		response = sendWithProof(requestSupplier, proof);
		Nonce refreshedNonce = response.getDPoPNonce();
		return new Outcome(response, proof, serverNonce, true,
				refreshedNonce != null ? refreshedNonce : serverNonce);
	}

	private static HTTPResponse sendWithProof(RequestSupplier requestSupplier, SignedJWT proof) throws Exception
	{
		HTTPRequest httpRequest = requestSupplier.get();
		httpRequest.setDPoP(proof);
		return httpRequest.send();
	}

	/**
	 * A nonce challenge is signalled with {@code use_dpop_nonce} - in the JSON error body by the token
	 * endpoint (HTTP 400) and in the {@code WWW-Authenticate} header by a resource server (HTTP 401). The
	 * nonce itself always comes in the {@code DPoP-Nonce} header, without which there is nothing to retry
	 * with.
	 */
	private static boolean requiresNonce(HTTPResponse response)
	{
		if (response.getDPoPNonce() == null || response.getStatusCode() < 400)
			return false;
		String wwwAuthenticate = response.getHeaderValue("WWW-Authenticate");
		if (wwwAuthenticate != null && wwwAuthenticate.contains(USE_DPOP_NONCE))
			return true;
		String body = response.getBody();
		return body != null && body.contains(USE_DPOP_NONCE);
	}
}
