package org.kairosdb.security.oauth2.core.client;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class OAuthenticatingClientTest
{
    private static final String internalToken = "ef3ad192-e265-4d12-9d09-0975fa8e1504";
    private static URI originUri;
    private static OAuthenticatingClient oAuthClient;

    @BeforeClass
    public static void setup() throws URISyntaxException
    {
        originUri = new URI("http://google.fr");
        oAuthClient = new OAuthenticatingClient(internalToken, originUri, 0) {};
    }

    @Test
    public void getOriginUri() throws Exception
    {
        Assert.assertEquals(originUri, oAuthClient.getOriginUri());
    }

    @Test
    public void getInternalToken() throws Exception
    {
        Assert.assertEquals(internalToken, oAuthClient.getInternalToken());
    }

    @Test
    public void getAccessToken() throws Exception
    {
        Assert.assertEquals("", oAuthClient.getAccessToken());
    }

    @Test
    public void getUserIdentifier() throws Exception
    {
        Assert.assertEquals("", oAuthClient.getUserIdentifier());
    }

    @Test
    public void isAuthenticated() throws Exception
    {
        Assert.assertFalse(oAuthClient.isAuthenticated());
    }

    @Test
    public void isObsolete() throws Exception
    {
        final OAuthClient client = new OAuthenticatingClient(internalToken, originUri, 2) {};

        Assert.assertFalse(client.isObsolete(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())));
        Thread.sleep(2000);
        Assert.assertTrue(client.isObsolete(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())));
    }

    @Test
    public void compareTo() throws Exception
    {
        final OAuthClient authenticatedClient = new OAuthenticatedClient(internalToken, "", "", 0);
        final List<OAuthClient> clientsWithDifferentInternalToken = new ArrayList<>();
        clientsWithDifferentInternalToken.add(0, new OAuthenticatingClient("a", originUri, 0) {});
        clientsWithDifferentInternalToken.add(1, new OAuthenticatingClient("z", originUri, 0) {});

        Assert.assertTrue(oAuthClient.compareTo(authenticatedClient) > 0);
        Assert.assertTrue(oAuthClient.compareTo(clientsWithDifferentInternalToken.get(0)) > 0);
        Assert.assertTrue(oAuthClient.compareTo(clientsWithDifferentInternalToken.get(1)) < 0);
    }

}