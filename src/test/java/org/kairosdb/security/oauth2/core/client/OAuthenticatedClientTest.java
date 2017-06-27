package org.kairosdb.security.oauth2.core.client;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class OAuthenticatedClientTest
{
    private static final String internalToken = String.valueOf(OAuthenticatedClientTest.class.hashCode());
    private static final String userIdentifier = "e6f268b1-4f09-4370-857f-618fdf82067a";
    private static final String accessToken = "267b215c-25a5-4daa-9d47-9c60746828c9";
    private static OAuthClient oAuthClient;

    @BeforeClass
    public static void setup()
    {
        oAuthClient = new OAuthenticatedClient(internalToken, accessToken, userIdentifier, 0);
    }

    @Test
    public void getInternalToken() throws Exception
    {
        Assert.assertEquals(internalToken, oAuthClient.getInternalToken());
    }

    @Test
    public void getAccessToken() throws Exception
    {
        Assert.assertEquals(accessToken, oAuthClient.getAccessToken());
    }

    @Test
    public void getUserIdentifier() throws Exception
    {
        Assert.assertEquals(userIdentifier, oAuthClient.getUserIdentifier());
    }

    @Test
    public void isAuthenticated() throws Exception
    {
        Assert.assertTrue(oAuthClient.isAuthenticated());
    }

    @Test
    public void isObsolete() throws Exception
    {
        final OAuthClient client = new OAuthenticatedClient(internalToken, accessToken, userIdentifier, 2);

        Assert.assertFalse(client.isObsolete(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())));
        Thread.sleep(2000);
        Assert.assertTrue(client.isObsolete(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())));
    }

    @Test
    public void compareTo() throws Exception
    {
        final OAuthClient notAuthenticatedClient = new OAuthenticatingClient(accessToken, null, 0) {};
        final OAuthClient clientWithSameUserId = new OAuthenticatedClient(internalToken, accessToken, userIdentifier, 1000);
        final List<OAuthClient> clientsWithDifferentUserId = new ArrayList<>();
        clientsWithDifferentUserId.add(0, new OAuthenticatedClient(internalToken, accessToken, "a", 0));
        clientsWithDifferentUserId.add(1, new OAuthenticatedClient(internalToken, accessToken, "z", 0));

        Assert.assertTrue(oAuthClient.compareTo(notAuthenticatedClient) > 0);
        Assert.assertTrue(oAuthClient.compareTo(clientWithSameUserId) > 0);
        Assert.assertTrue(oAuthClient.compareTo(clientsWithDifferentUserId.get(0)) > 0);
        Assert.assertTrue(oAuthClient.compareTo(clientsWithDifferentUserId.get(1)) < 0);
    }

}