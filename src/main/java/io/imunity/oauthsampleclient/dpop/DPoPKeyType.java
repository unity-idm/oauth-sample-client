package io.imunity.oauthsampleclient.dpop;

import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

/**
 * Kinds of proof-of-possession keys which this client can generate for DPoP. Each one is bound to a single,
 * fixed JWS algorithm - the point of the choice is to exercise the different key families, not to make the
 * algorithm configurable.
 */
public enum DPoPKeyType
{
	EC("EC P-256", JWSAlgorithm.ES256),
	RSA("RSA 2048", JWSAlgorithm.RS256),
	EDDSA("OKP Ed25519", JWSAlgorithm.EdDSA);

	private final String label;
	private final JWSAlgorithm jwsAlgorithm;

	DPoPKeyType(String label, JWSAlgorithm jwsAlgorithm)
	{
		this.label = label;
		this.jwsAlgorithm = jwsAlgorithm;
	}

	public String getLabel()
	{
		return label;
	}

	public JWSAlgorithm getJwsAlgorithm()
	{
		return jwsAlgorithm;
	}

	JWK generateKey() throws JOSEException
	{
		String keyId = UUID.randomUUID().toString();
		return switch (this)
		{
			case EC -> new ECKeyGenerator(Curve.P_256)
					.keyID(keyId).keyUse(KeyUse.SIGNATURE).algorithm(jwsAlgorithm).generate();
			case RSA -> new RSAKeyGenerator(2048)
					.keyID(keyId).keyUse(KeyUse.SIGNATURE).algorithm(jwsAlgorithm).generate();
			case EDDSA -> new OctetKeyPairGenerator(Curve.Ed25519)
					.keyID(keyId).keyUse(KeyUse.SIGNATURE).algorithm(jwsAlgorithm).generate();
		};
	}
}
