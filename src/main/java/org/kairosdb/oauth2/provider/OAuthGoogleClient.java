package org.kairosdb.oauth2.provider;

import org.kairosdb.core.oauth2.client.OAuthenticatingClient;

import java.net.URI;

class OAuthGoogleClient extends OAuthenticatingClient
{
    OAuthGoogleClient(URI originUri)
    {
        super(String.valueOf(System.nanoTime()), originUri, 300);
    }
}
