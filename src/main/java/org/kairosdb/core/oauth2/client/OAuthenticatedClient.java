package org.kairosdb.core.oauth2.client;

import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;

import java.util.concurrent.TimeUnit;

public final class OAuthenticatedClient implements OAuthClient
{
    private String internalToken;
    private String accessToken;
    private String userIdentifier;
    private long startTime;
    private long endTime;


    OAuthenticatedClient(String internalToken, String accessToken, String userIdentifier, long expireIn)
    {
        this.internalToken = internalToken;
        this.accessToken = accessToken;
        this.userIdentifier = userIdentifier;
        this.startTime = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
        this.endTime = this.startTime + expireIn;
    }


    public String getInternalToken()
    {
        return internalToken;
    }

    public String getAccessToken()
    {
        return accessToken;
    }

    public String getUserIdentifier()
    {
        return userIdentifier;
    }

    public boolean isAuthenticated()
    {
        return true;
    }

    public boolean isObsolete(long currentTime)
    {
        return currentTime >= endTime;
    }


    public int compareTo(OAuthClient anotherClient)
    {
        if (!(anotherClient instanceof OAuthenticatedClient))
            return 0;

        final OAuthenticatedClient client = (OAuthenticatedClient) anotherClient;
        if (!userIdentifier.equals(client.userIdentifier))
            return userIdentifier.compareTo(client.userIdentifier);
        return (startTime - client.startTime <= 0) ? -1 : 1;
    }

    public static class Builder
    {
        String internalToken;
        String accessToken;
        String userIdentifier;
        long expireIn = Long.MIN_VALUE;

        public Builder setInternalToken(String internalToken)
        {
            this.internalToken = internalToken;
            return this;
        }

        public Builder setAccessToken(String accessToken)
        {
            this.accessToken = accessToken;
            return this;
        }

        public Builder setUserIdentifier(String userIdentifier)
        {
            this.userIdentifier = userIdentifier;
            return this;
        }

        public Builder setExpireIn(long expireIn)
        {
            this.expireIn = expireIn;
            return this;
        }

        public OAuthenticatedClient build() throws OAuthFlowException
        {
            if (internalToken == null || accessToken == null || userIdentifier == null || expireIn == Long.MIN_VALUE)
                throw new OAuthFlowException("All information are not set. Impossible to generate 'OAuthenticatedClient'.");
            return new OAuthenticatedClient(internalToken, accessToken, userIdentifier, expireIn);
        }
    }
}
