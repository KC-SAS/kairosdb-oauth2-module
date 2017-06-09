package org.kairosdb.core.oauth2.client;

import java.net.URI;
import java.util.concurrent.TimeUnit;

public abstract class OAuthenticatingClient implements OAuthClient
{
    protected String temporaryToken;
    protected long endTime;
    protected URI originUri;

    protected OAuthenticatingClient(String temporaryToken, URI originUri, long lifeTime)
    {
        this.temporaryToken = temporaryToken;
        this.originUri = originUri;
        this.endTime = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()) + TimeUnit.MINUTES.toSeconds(lifeTime);
    }


    public URI getOriginUri()
    {
        return originUri;
    }

    public String getInternalToken()
    {
        return temporaryToken;
    }

    public String getAccessToken()
    {
        return null;
    }

    public String getUserIdentifier()
    {
        return null;
    }

    public boolean isAuthenticated()
    {
        return false;
    }

    public boolean isObsolete(long currentTime)
    {
        return currentTime >= endTime;
    }


    public final int compareTo(OAuthClient anotherClient)
    {
        if (anotherClient.isAuthenticated())
            return 1;
        return getInternalToken().compareTo(anotherClient.getInternalToken());
    }
}
