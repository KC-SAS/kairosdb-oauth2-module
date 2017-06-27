package org.kairosdb.security.oauth2.core.client;

import org.junit.Assert;
import org.junit.Test;
import org.kairosdb.security.oauth2.core.exception.OAuthFlowException;

import java.util.concurrent.TimeUnit;

public class BuilderTest
{
    private static final String internalToken = "dab690b6-c5ed-46ed-853c-53b575f7f3d0";
    private static final String accessToken = "e02bd0b7-f665-40e3-8a25-e8d50e55babc";
    private static final String userIdentifier = "1a0cf0a0-b52f-47d3-bd5e-92c48f80400f";
    private static final int expireIn = 1024;

    @Test
    public void setInternalToken() throws Exception
    {
        final OAuthenticatedClient.Builder builder = new OAuthenticatedClient.Builder();

        builder.setInternalToken(internalToken);
        Assert.assertEquals(internalToken, builder.internalToken);
    }

    @Test
    public void setAccessToken() throws Exception
    {
        final OAuthenticatedClient.Builder builder = new OAuthenticatedClient.Builder();

        builder.setAccessToken(accessToken);
        Assert.assertEquals(accessToken, builder.accessToken);
    }

    @Test
    public void setUserIdentifier() throws Exception
    {
        final OAuthenticatedClient.Builder builder = new OAuthenticatedClient.Builder();

        builder.setUserIdentifier(userIdentifier);
        Assert.assertEquals(userIdentifier, builder.userIdentifier);
    }

    @Test
    public void setExpireIn() throws Exception
    {
        final OAuthenticatedClient.Builder builder = new OAuthenticatedClient.Builder();

        builder.setExpireIn(expireIn);
        Assert.assertEquals(expireIn, builder.expireIn);
    }

    @Test
    public void build() throws OAuthFlowException
    {
        final OAuthenticatedClient.Builder builder = new OAuthenticatedClient.Builder();

        builder.setInternalToken(internalToken)
                .setAccessToken(accessToken)
                .setUserIdentifier(userIdentifier)
                .setExpireIn(0);

        final OAuthenticatedClient client = builder.build();

        Assert.assertEquals(internalToken, client.getInternalToken());
        Assert.assertEquals(accessToken, client.getAccessToken());
        Assert.assertEquals(userIdentifier, client.getUserIdentifier());
        Assert.assertTrue(client.isObsolete(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())));
    }

    @Test(expected = OAuthFlowException.class)
    public void build_exception() throws OAuthFlowException
    {
        final OAuthenticatedClient.Builder builder = new OAuthenticatedClient.Builder();
        builder.build();
    }

}