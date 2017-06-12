package org.kairosdb.core.oauth2.provider;

import org.kairosdb.core.oauth2.OAuthService;
import org.kairosdb.core.oauth2.client.OAuthenticatedClient;
import org.kairosdb.core.oauth2.client.OAuthenticatingClient;
import org.kairosdb.core.oauth2.exceptions.OAuthConfigurationException;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;

import java.net.URI;
import java.util.Properties;
import java.util.function.Function;

/**
 * Interface for OAuthProvider implementation
 */
public interface OAuthProvider
{
    /**
     * Setup the client identifier (applicationToken and secretToken)
     * to bind your application with the provider
     *
     * @param clientId     client ID of your client credential
     * @param clientSecret client secret of your client credential
     * @return self instance ({@link OAuthProvider}) to chain setup methods
     */
    OAuthProvider setup(String clientId, String clientSecret);

    /**
     * Setup the URI where the provider redirect yours application
     * users after authentication
     *
     * @param redirectUri URI of the redirection
     * @return self instance ({@link OAuthProvider}) to chain setup methods
     */
    OAuthProvider setup(String redirectUri);

    /**
     * If the provider need more information (like scope for Google),
     * you can get it here.
     * <p><i>(See the provider documentation for more information)</i></p>
     *
     * @param properties Property file
     * @return self instance ({@link OAuthProvider}) to chain setup methods
     */
    OAuthProvider setup(Properties properties) throws OAuthConfigurationException;

    /**
     * Configure the OAuthProvider with settings
     */
    void configure() throws OAuthConfigurationException;

    /**
     * Check if the provider is already configured
     *
     * @return {@code true} if is configured, else {@code false}
     */
    boolean isConfigured();

    /**
     * Start authentication flow with OAuth2.
     *
     * @param originUri uri to redirect user when the authentication flow is finished
     * @return {@link OAuthService.OAuthProviderResponse} containing
     * the configured {@link OAuthenticatingClient} and
     * information needed to redirect the user
     */
    OAuthService.OAuthProviderResponse startAuthentication(URI originUri) throws OAuthFlowException;

    /**
     * Finish authentication flow with OAuth2.
     *
     * @param code                   code return by the provider during redirection
     * @param state                  state return by the provider during redirection
     * @param internalTokenGenerator function required to generate internalToken
     * @return {@link OAuthService.OAuthProviderResponse} containing
     * the configured {@link OAuthenticatedClient} and
     * information needed to redirect the user
     */
    OAuthService.OAuthProviderResponse finishAuthentication(OAuthenticatingClient oAuthenticatingClient,
                                                            String code, String state,
                                                            Function<String, String> internalTokenGenerator)
            throws OAuthFlowException;
}
