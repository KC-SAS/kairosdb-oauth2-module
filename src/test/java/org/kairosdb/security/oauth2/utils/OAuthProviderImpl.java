package org.kairosdb.security.oauth2.utils;

import org.kairosdb.security.oauth2.core.OAuthProvider;
import org.kairosdb.security.oauth2.core.OAuthService;
import org.kairosdb.security.oauth2.core.client.OAuthClient;
import org.kairosdb.security.oauth2.core.client.OAuthenticatedClient;
import org.kairosdb.security.oauth2.core.client.OAuthenticatingClient;
import org.kairosdb.security.oauth2.core.exception.OAuthConfigurationException;
import org.kairosdb.security.oauth2.core.exception.OAuthFlowException;

import java.net.URI;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Function;

public class OAuthProviderImpl implements OAuthProvider
{
    @Override
    public OAuthProvider setup(String clientId, String clientSecret)
    {
        return this;
    }

    @Override
    public OAuthProvider setup(String redirectUri)
    {
        return this;
    }

    @Override
    public OAuthProvider setup(Properties properties) throws OAuthConfigurationException
    {
        return this;
    }

    @Override
    public void configure() throws OAuthConfigurationException
    {

    }

    @Override
    public boolean isConfigured()
    {
        return false;
    }

    @Override
    public OAuthService.OAuthProviderResponse startAuthentication(URI originUri) throws OAuthFlowException
    {
        try
        {
            return new OAuthService.OAuthProviderResponse(
                    new OAuthenticatingClient(UUID.randomUUID().toString(), new URI("http://google.com"), 3600) {},
                    new URI("http://google.com"),
                    null
            );
        } catch (Exception e)
        {
            throw new OAuthFlowException(e);
        }
    }

    @Override
    public OAuthService.OAuthProviderResponse finishAuthentication(OAuthenticatingClient oAuthenticatingClient, String code, String state, Function<String, String> internalTokenGenerator) throws OAuthFlowException
    {
        final String accessToken = UUID.randomUUID().toString();
        OAuthClient client = new OAuthenticatedClient.Builder()
                .setAccessToken(accessToken)
                .setInternalToken(internalTokenGenerator.apply(accessToken))
                .setUserIdentifier(UUID.randomUUID().toString())
                .setExpireIn(0)
                .build();

        try
        {
            return new OAuthService.OAuthProviderResponse(client, new URI("http://google.fr"), null);
        } catch (Exception e)
        {
            throw new OAuthFlowException(e);
        }
    }
}
