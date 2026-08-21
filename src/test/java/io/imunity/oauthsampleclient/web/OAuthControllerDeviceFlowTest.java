package io.imunity.oauthsampleclient.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.mock.web.MockHttpSession;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.imunity.oauthsampleclient.config.ClientDefaults;
import io.imunity.oauthsampleclient.web.OAuthController.OAuthForm;

class OAuthControllerDeviceFlowTest
{
	private static final String DEVICE_SUCCESS = """
			{
			  "device_code": "device-secret",
			  "user_code": "ABCD-EFGH",
			  "verification_uri": "https://as.example/activate",
			  "verification_uri_complete": "https://as.example/activate?user_code=ABCD-EFGH",
			  "expires_in": 600,
			  "interval": 2
			}
			""";

	private HttpServer authorizationServer;
	private String serverBaseUri;
	private MutableClock clock;

	@BeforeEach
	void startServer() throws IOException
	{
		authorizationServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
		authorizationServer.start();
		serverBaseUri = "http://localhost:" + authorizationServer.getAddress().getPort();
		clock = new MutableClock(Instant.parse("2026-08-21T10:00:00Z"));
	}

	@AfterEach
	void stopServer()
	{
		authorizationServer.stop(0);
	}

	@Test
	void pollsPendingAndSlowDownResponsesUntilTokensAreReturned() throws Exception
	{
		AtomicReference<Map<String, String>> deviceRequest = new AtomicReference<>();
		authorizationServer.createContext("/device", exchange -> {
			deviceRequest.set(readForm(exchange));
			respond(exchange, 200, DEVICE_SUCCESS);
		});

		AtomicInteger tokenRequests = new AtomicInteger();
		AtomicReference<Map<String, String>> tokenRequest = new AtomicReference<>();
		authorizationServer.createContext("/token", exchange -> {
			tokenRequest.set(readForm(exchange));
			int requestNumber = tokenRequests.incrementAndGet();
			if (requestNumber == 1)
				respond(exchange, 400, "{\"error\":\"authorization_pending\"}");
			else if (requestNumber == 2)
				respond(exchange, 400, "{\"error\":\"slow_down\"}");
			else
				respond(exchange, 200,
						"{\"access_token\":\"access-token\",\"token_type\":\"Bearer\",\"expires_in\":300}");
		});

		OAuthController controller = new OAuthController(new ClientDefaults(), clock);
		MockHttpSession session = new MockHttpSession();
		Model startModel = new ExtendedModelMap();

		assertThat(controller.startDeviceAuth(form(), session, startModel)).isEqualTo("device");
		assertThat(startModel.getAttribute("userCode")).isEqualTo("ABCD-EFGH");
		assertThat(startModel.getAttribute("verificationUri")).isEqualTo("https://as.example/activate");
		assertThat(startModel.getAttribute("verificationUriComplete"))
				.isEqualTo("https://as.example/activate?user_code=ABCD-EFGH");
		assertThat(startModel.getAttribute("pollingIntervalSeconds")).isEqualTo(2L);
		assertThat(deviceRequest.get()).containsEntry("client_id", "test-client")
				.containsEntry("scope", "openid profile");

		clock.advanceSeconds(2);
		Model pendingModel = new ExtendedModelMap();
		assertThat(controller.pollDeviceToken(session, pendingModel)).isEqualTo("device");
		assertThat(pendingModel.getAttribute("pollStatus")).isEqualTo("Authorization is still pending.");
		assertThat(tokenRequest.get()).containsEntry("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
				.containsEntry("device_code", "device-secret")
				.containsEntry("client_id", "test-client");

		clock.advanceSeconds(2);
		Model slowDownModel = new ExtendedModelMap();
		assertThat(controller.pollDeviceToken(session, slowDownModel)).isEqualTo("device");
		assertThat(slowDownModel.getAttribute("pollingIntervalSeconds")).isEqualTo(7L);
		assertThat(tokenRequests).hasValue(2);

		clock.advanceSeconds(2);
		Model earlyPollModel = new ExtendedModelMap();
		assertThat(controller.pollDeviceToken(session, earlyPollModel)).isEqualTo("device");
		assertThat(earlyPollModel.getAttribute("pollDelaySeconds")).isEqualTo(5L);
		assertThat(tokenRequests).hasValue(2);

		clock.advanceSeconds(5);
		Model resultModel = new ExtendedModelMap();
		assertThat(controller.pollDeviceToken(session, resultModel)).isEqualTo("result");
		assertThat(resultModel.getAttribute("parsedResponse").toString()).contains("access-token");
		assertThat(resultModel.getAttribute("accessToken")).isEqualTo("access-token");
		assertThat(session.getAttribute(OAuthController.DEVICE_SESSION_STATE)).isNull();
		assertThat(tokenRequests).hasValue(3);
	}

	@Test
	void presentsDeviceAuthorizationErrorsWithoutStartingPolling()
	{
		authorizationServer.createContext("/device", exchange ->
				respond(exchange, 400, "{\"error\":\"invalid_client\",\"error_description\":\"Unknown client\"}"));

		OAuthController controller = new OAuthController(new ClientDefaults(), clock);
		MockHttpSession session = new MockHttpSession();
		Model model = new ExtendedModelMap();

		assertThat(controller.startDeviceAuth(form(), session, model)).isEqualTo("device");
		assertThat(model.getAttribute("deviceError").toString())
				.contains("invalid_client")
				.contains("Unknown client");
		assertThat(model.getAttribute("deviceRawResponse").toString()).contains("HTTP 400");
		assertThat(session.getAttribute(OAuthController.DEVICE_SESSION_STATE)).isNull();
	}

	@Test
	void presentsTerminalTokenErrorsOnTheResultPage()
	{
		authorizationServer.createContext("/device", exchange -> respond(exchange, 200, DEVICE_SUCCESS));
		authorizationServer.createContext("/token", exchange ->
				respond(exchange, 400, "{\"error\":\"access_denied\",\"error_description\":\"User declined\"}"));

		OAuthController controller = new OAuthController(new ClientDefaults(), clock);
		MockHttpSession session = new MockHttpSession();
		assertThat(controller.startDeviceAuth(form(), session, new ExtendedModelMap())).isEqualTo("device");

		clock.advanceSeconds(2);
		Model resultModel = new ExtendedModelMap();
		assertThat(controller.pollDeviceToken(session, resultModel)).isEqualTo("result");
		assertThat(resultModel.getAttribute("oauthError").toString())
				.contains("access_denied")
				.contains("User declined");
		assertThat(resultModel.getAttribute("rawResponse").toString()).contains("HTTP 400");
		assertThat(session.getAttribute(OAuthController.DEVICE_SESSION_STATE)).isNull();
	}

	private OAuthForm form()
	{
		OAuthForm form = new OAuthForm();
		form.setDeviceAuthorizationEndpoint(serverBaseUri + "/device");
		form.setTokenEndpoint(serverBaseUri + "/token");
		form.setClientId("test-client");
		form.setScope("openid profile");
		form.setDevicePollingIntervalSeconds(1);
		return form;
	}

	private static Map<String, String> readForm(HttpExchange exchange) throws IOException
	{
		String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
		Map<String, String> values = new LinkedHashMap<>();
		Arrays.stream(body.split("&"))
				.map(pair -> pair.split("=", 2))
				.forEach(pair -> values.put(decode(pair[0]), pair.length > 1 ? decode(pair[1]) : ""));
		return values;
	}

	private static String decode(String value)
	{
		return URLDecoder.decode(value, StandardCharsets.UTF_8);
	}

	private static void respond(HttpExchange exchange, int status, String body) throws IOException
	{
		byte[] content = body.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, content.length);
		exchange.getResponseBody().write(content);
		exchange.close();
	}

	private static class MutableClock extends Clock
	{
		private Instant instant;

		MutableClock(Instant instant)
		{
			this.instant = instant;
		}

		void advanceSeconds(long seconds)
		{
			instant = instant.plusSeconds(seconds);
		}

		@Override
		public ZoneId getZone()
		{
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(ZoneId zone)
		{
			return this;
		}

		@Override
		public Instant instant()
		{
			return instant;
		}
	}
}
