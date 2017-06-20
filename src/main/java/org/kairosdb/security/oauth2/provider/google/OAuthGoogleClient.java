package org.kairosdb.security.oauth2.provider.google;

import org.kairosdb.security.oauth2.core.client.OAuthenticatingClient;

import java.net.URI;

class OAuthGoogleClient extends OAuthenticatingClient
{
    OAuthGoogleClient(URI originUri)
    {
        super(String.valueOf(System.nanoTime()), originUri, 300);
    }
}
