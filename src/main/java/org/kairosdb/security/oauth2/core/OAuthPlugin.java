package org.kairosdb.security.oauth2.core;

import org.kairosdb.security.auth.core.exception.UnauthorizedClientResponse;
import org.kairosdb.security.oauth2.core.client.OAuthenticatedClient;

import javax.servlet.ServletRequest;
import java.util.Properties;

public interface OAuthPlugin
{
    /**
     * Configure OAuth plugin with {@link Properties}
     *
     * @param properties {@link Properties}, may required for configuration
     */
    void configure(Properties properties);

    /**
     * Check if the user is allowed to access to resources.
     *
     * @param client {@link OAuthenticatedClient} requested for checking
     * @param httpRequest {@link ServletRequest} request if need external information
     * @return {@code true} if allowed, else {@code false}
     */
    boolean isAllowed(OAuthenticatedClient client, ServletRequest httpRequest) throws UnauthorizedClientResponse;
}
