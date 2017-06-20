package org.kairosdb.security.oauth2.core;

import org.kairosdb.security.auth.core.exception.UnauthorizedClientResponse;
import org.kairosdb.security.oauth2.core.client.OAuthClient;

import javax.servlet.ServletRequest;
import java.util.Properties;

public interface OAuthPlugin
{
    void configure(Properties properties);
    boolean isAllowed(OAuthClient client, ServletRequest httpRequest) throws UnauthorizedClientResponse;
}
