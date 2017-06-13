package org.kairosdb.core.oauth2.filter;

import org.kairosdb.core.oauth2.client.OAuthClient;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public interface OAuthFilter
{
    void doFilter(ServletRequest httpRequest, ServletResponse httpResponse, OAuthClient client);
}
