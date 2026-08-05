package io.imunity.oauthsampleclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class OAuthSampleClientApplication
{
	public static void main(String[] args)
	{
		SpringApplication.run(OAuthSampleClientApplication.class, args);
	}
}
