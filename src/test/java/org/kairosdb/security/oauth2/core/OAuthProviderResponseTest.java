package org.kairosdb.security.oauth2.core;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.kairosdb.security.oauth2.core.client.OAuthClient;
import org.kairosdb.security.oauth2.core.client.OAuthenticatedClient;
import org.kairosdb.security.oauth2.core.exception.OAuthFlowException;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

public class OAuthProviderResponseTest
{
    private static final Map<String, String> headers = new HashMap<>();
    private static URI redirectUri;
    private static OAuthClient client;
    private static OAuthService.OAuthProviderResponse oAuthProviderResponse;

    @BeforeClass
    public static void setup() throws URISyntaxException, OAuthFlowException
    {
        headers.put("Key", "Value");
        redirectUri = new URI("http://google.fr");
        client = new OAuthenticatedClient.Builder()
                .setAccessToken("")
                .setInternalToken("")
                .setUserIdentifier("")
                .setExpireIn(0)
                .build();

        oAuthProviderResponse = new OAuthService.OAuthProviderResponse(client, redirectUri, headers);
    }

    @Test
    public void getClient() throws Exception
    {
        Assert.assertEquals(client, oAuthProviderResponse.getClient());
    }

    @Test
    public void getRedirectUri() throws Exception
    {
        Assert.assertEquals(redirectUri, oAuthProviderResponse.getRedirectUri());
    }

    @Test
    public void getHeaders() throws Exception
    {
        Assert.assertEquals(headers, oAuthProviderResponse.getHeaders());
    }
}