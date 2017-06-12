package org.kairosdb.oauth2.provider;


import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.OAuthProviderType;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONObject;
import org.kairosdb.core.oauth2.OAuthService;
import org.kairosdb.core.oauth2.client.OAuthenticatedClient;
import org.kairosdb.core.oauth2.client.OAuthenticatingClient;
import org.kairosdb.core.oauth2.exceptions.OAuthConfigurationException;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;
import org.kairosdb.core.oauth2.provider.OAuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Properties;
import java.util.function.Function;

public class OAuthGoogleProvider implements OAuthProvider
{
    private static String GOOGLE_SCOPE_PREFIX = "kairosdb.oauth2.google.scope";
    private static String GOOGLE_USER_INFO = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
    private static Logger logger = LoggerFactory.getLogger(OAuthGoogleProvider.class);

    private OAuthClientRequest.AuthenticationRequestBuilder authRequestBuilder;
    private OAuthClientRequest.TokenRequestBuilder tokenRequestBuilder;
    private String scope;
    private boolean isConfigured = false;


    OAuthGoogleProvider()
    {
        authRequestBuilder = OAuthClientRequest
                .authorizationProvider(OAuthProviderType.GOOGLE)
                .setResponseType(OAuth.OAUTH_CODE);
        tokenRequestBuilder = OAuthClientRequest
                .tokenProvider(OAuthProviderType.GOOGLE)
                .setGrantType(GrantType.AUTHORIZATION_CODE);
    }


    @Override
    public OAuthProvider setup(String clientId, String clientSecret)
    {
        authRequestBuilder
                .setClientId(clientId);
        tokenRequestBuilder
                .setClientId(clientId)
                .setClientSecret(clientSecret);
        return this;
    }

    @Override
    public OAuthProvider setup(String redirectUri)
    {
        authRequestBuilder.setRedirectURI(redirectUri);
        tokenRequestBuilder.setRedirectURI(redirectUri);
        return this;
    }

    @Override
    public OAuthProvider setup(Properties properties) throws OAuthConfigurationException
    {
        this.scope = (String) properties.get(GOOGLE_SCOPE_PREFIX);
        return this;
    }

    @Override
    public void configure() throws OAuthConfigurationException
    {
        if (this.scope == null)
            throw new OAuthConfigurationException(GOOGLE_SCOPE_PREFIX);
        authRequestBuilder.setScope(scope);

        logger.info(String.format("%s is now configured.", getClass().getName()));
        isConfigured = true;
    }


    @Override
    public boolean isConfigured()
    {
        return isConfigured;
    }

    @Override
    public OAuthService.OAuthProviderResponse startAuthentication(URI originUri)
            throws OAuthFlowException
    {
        logger.info(String.format("Start authentication from '%s'.", concatUri(originUri)));

        try
        {
            final OAuthClientRequest oAuthClientRequest = authRequestBuilder.buildQueryMessage();
            final URI redirectUri = new URI(oAuthClientRequest.getLocationUri());
            final OAuthGoogleClient googleClient = new OAuthGoogleClient(originUri);

            logger.info(String.format("Redirect user to '%s'.", concatUri(originUri)));
            return new OAuthService.OAuthProviderResponse(
                    googleClient,
                    redirectUri,
                    oAuthClientRequest.getHeaders(),
                    oAuthClientRequest.getBody()
            );

        } catch (Exception e)
        {
            throw new OAuthFlowException(e.getMessage());
        }
    }

    @Override
    public OAuthService.OAuthProviderResponse finishAuthentication(
            OAuthenticatingClient oAuthenticatingClient,
            String code, String state,
            Function<String, String> internalTokenGenerator
    ) throws OAuthFlowException
    {
        logger.info(String.format(
                "Finish authentication from '%s' ('%s').",
                concatUri(oAuthenticatingClient.getOriginUri()),
                oAuthenticatingClient.getAccessToken())
        );

        try
        {
            final OAuthClientRequest oAuthClientRequest = tokenRequestBuilder.setCode(code).buildBodyMessage();
            final OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            final OAuthAccessTokenResponse tokenResponse = oAuthClient.accessToken(oAuthClientRequest);

            final String accessToken = tokenResponse.getAccessToken();
            final OAuthenticatedClient authenticatedClient = new OAuthenticatedClient.Builder()
                    .setInternalToken(internalTokenGenerator.apply(accessToken))
                    .setAccessToken(accessToken)
                    .setExpireIn(tokenResponse.getExpiresIn())
                    .setUserIdentifier(getUserIdentifier(oAuthClient, accessToken))
                    .build();

            logger.info(String.format("User '%s' authenticated", authenticatedClient.getUserIdentifier()));
            return new OAuthService.OAuthProviderResponse(
                    authenticatedClient,
                    oAuthenticatingClient.getOriginUri(),
                    null,
                    null
            );
        } catch (Exception e)
        {
            throw new OAuthFlowException(e.getMessage());
        }

    }


    private String concatUri(URI uri)
    {
        String sUri = uri.toString();
        if (sUri.length() < 64)
            return sUri;
        return sUri.substring(0, 64) + "...";
    }

    private String getUserIdentifier(OAuthClient oAuthClient, String accessToken)
            throws OAuthSystemException, OAuthProblemException
    {
        final OAuthClientRequest bearerClientRequest = new OAuthBearerClientRequest(GOOGLE_USER_INFO)
                .setAccessToken(accessToken)
                .buildHeaderMessage();
        final OAuthResourceResponse resourceResponse = oAuthClient.resource(
                bearerClientRequest,
                OAuth.HttpMethod.GET,
                OAuthResourceResponse.class
        );
        JSONObject jsonObject = new JSONObject(resourceResponse.getBody());
        return jsonObject.get("id").toString();
    }
}
