package org.kairosdb.core.oauth2;


import com.google.inject.Inject;
import org.kairosdb.core.oauth2.client.OAuthClient;
import org.kairosdb.core.oauth2.client.OAuthenticatedClient;
import org.kairosdb.core.oauth2.client.OAuthenticatingClient;
import org.kairosdb.core.oauth2.cookie.OAuthCookieManager;
import org.kairosdb.core.oauth2.exceptions.OAuthConfigurationException;
import org.kairosdb.core.oauth2.exceptions.OAuthFlowException;
import org.kairosdb.core.oauth2.exceptions.OAuthValidationException;
import org.kairosdb.core.oauth2.provider.OAuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;


public class OAuthService
{
    private static final Logger logger = LoggerFactory.getLogger(OAuthService.class);

    private static final String CLIENT_ID_PREFIX = "kairosdb.oauth2.clientId";
    private static final String CLIENT_SECRET_PREFIX = "kairosdb.oauth2.clientSecret";
    private static final String REDIRECTION_URI_PREFIX = "kairosdb.oauth2.redirectionUri";

    private static final String[] HeaderClientIpList =
            {
                    "X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP",
                    "HTTP_X_FORWARDED_FOR", "HTTP_X_CLUSTER_CLIENT_IP", "HTTP_CLIENT_IP",
                    "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_VIA", "REMOTE_ADDR"
            };

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;

    private final Map<String, OAuthClient> clients = new HashMap<>();
    private final OAuthProvider provider;
    private final OAuthCookieManager cookieManager;


    @Inject
    public OAuthService(OAuthProvider provider,
                        OAuthCookieManager cookieManager,
                        Properties properties)
    {
        this.clientId = properties.getProperty(CLIENT_ID_PREFIX);
        this.clientSecret = properties.getProperty(CLIENT_SECRET_PREFIX);
        this.redirectUri = properties.getProperty(REDIRECTION_URI_PREFIX);
        this.cookieManager = cookieManager;
        this.provider = provider.setup(properties);
    }


    //region Static tools methods
    public static void validateProperty(String property, String prefix)
    {
        if (property == null || property.isEmpty())
            throw new OAuthConfigurationException(prefix);
    }

    private static String retrieveRemoteAddress(HttpServletRequest request)
    {
        String remoteAddress;

        for (String header : HeaderClientIpList)
        {
            remoteAddress = request.getHeader(header);
            if (remoteAddress != null && !remoteAddress.isEmpty() && !remoteAddress.equalsIgnoreCase("unknown"))
            {
                if (!remoteAddress.contains(","))
                    return remoteAddress.trim();
                return new StringTokenizer(remoteAddress, ",").nextToken().trim();
            }
        }
        return request.getRemoteAddr();
    }

    private static String generateInternalToken(OAuthPacket packet, String accessToken)
    {
        String remoteAddress = packet.remoteAddr;

        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            if (accessToken != null)
                digest.update(accessToken.getBytes(StandardCharsets.UTF_8));
            digest.update(remoteAddress.getBytes(StandardCharsets.UTF_8));
            return new String(digest.digest(), StandardCharsets.UTF_8);
        } catch (Exception e)
        {
            logger.error("Failed to generate internal token with SHA-256. Switch to manual hashing method.", e);
            long hashcode = 17;
            if (accessToken != null)
                hashcode = 37 * hashcode + accessToken.hashCode();
            hashcode = 37 * hashcode + remoteAddress.hashCode();
            return String.valueOf(hashcode);
        }
    }

    private static void verifyTokenValidity(OAuthPacket packet, OAuthClient client)
            throws OAuthValidationException
    {
        final String currentInternalToken = generateInternalToken(packet, client.getAccessToken());
        if (!currentInternalToken.equals(client.getInternalToken()))
            throw new OAuthValidationException(currentInternalToken, client.getInternalToken());
    }
    //endregion


    //region OAuth methods
    private void isProviderConfigured()
    {
        if (provider.isConfigured())
            return;

        synchronized (this)
        {
            if (provider.isConfigured())
                return;

            validateProperty(this.clientId, CLIENT_ID_PREFIX);
            validateProperty(this.clientSecret, CLIENT_SECRET_PREFIX);
            validateProperty(this.redirectUri, REDIRECTION_URI_PREFIX);

            this.provider
                    .setup(this.redirectUri)
                    .setup(this.clientId, this.clientSecret)
                    .configure();
        }
    }

    public OAuthPacket startAuthentication(OAuthPacket requestPacket, URI originUri) throws OAuthFlowException
    {
        isProviderConfigured();

        final OAuthProviderResponse providerResponse = provider.startAuthentication(originUri);
        final OAuthClient oAuthClient = providerResponse.client;
        final OAuthPacket oAuthPacket = new OAuthPacket(
                requestPacket.remoteAddr,
                providerResponse.redirectUri,
                oAuthClient.getInternalToken(),
                cookieManager
        );

        addClient(oAuthClient);

        oAuthPacket.setHeaders(providerResponse.getHeaders());
        oAuthPacket.setBody(providerResponse.getBody());
        return oAuthPacket;
    }

    public OAuthPacket authorizeAuthentication(OAuthPacket requestPacket, String code, String state) throws OAuthFlowException
    {
        isProviderConfigured();

        final String internalToken = requestPacket.internalToken;
        OAuthClient oAuthClient = getClient(requestPacket);

        if (oAuthClient == null)
            throw new OAuthFlowException("Invalid authorization (User not found)");
        if (oAuthClient instanceof OAuthenticatedClient)
            throw new OAuthFlowException("Invalid authorization (User already authenticated)");


        final OAuthProviderResponse providerResponse = provider.finishAuthentication(
                (OAuthenticatingClient) oAuthClient,
                code, state,
                (String accessToken) -> generateInternalToken(requestPacket, accessToken)
        );
        oAuthClient = providerResponse.client;

        final OAuthPacket oAuthPacket = new OAuthPacket(
                requestPacket.remoteAddr,
                providerResponse.redirectUri,
                oAuthClient.getInternalToken(),
                cookieManager
        );

        removeClient(internalToken);

        try
        {
            verifyTokenValidity(requestPacket, oAuthClient);
        } catch (OAuthValidationException e)
        {
            throw new OAuthFlowException("Invalid provider : It doesn't use internal token generator");
        }

        addClient(oAuthClient);

        oAuthPacket.setHeaders(providerResponse.getHeaders());
        oAuthPacket.setBody(providerResponse.getBody());
        return oAuthPacket;
    }
    //endregion

    //region Client tools methods
    private synchronized void addClient(OAuthClient oAuthClient)
    {
        clients.put(oAuthClient.getInternalToken(), oAuthClient);
    }

    private synchronized void removeClient(String internalToken)
    {
        if (internalToken != null && clients.containsKey(internalToken))
            clients.remove(internalToken);
    }

    public OAuthClient getClient(OAuthPacket packet)
            throws OAuthValidationException
    {
        isProviderConfigured();

        final String internalToken = packet.internalToken;
        if (internalToken == null || !this.clients.containsKey(internalToken))
            return null;

        final OAuthClient client;
        synchronized (this)
        {
            client = this.clients.get(internalToken);
        }

        if (client.isObsolete(TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis())))
        {
            logger.warn(String.format("Client '%s' obsolete.", client.getUserIdentifier()));
            removeClient(client.getInternalToken());
            return null;
        }

        if (client instanceof OAuthenticatedClient)
            verifyTokenValidity(packet, client);
        return client;
    }

    public void verifyLifetime()
    {
        logger.info("Auto clean obsoleted user token");
        if (this.clients.isEmpty())
            return;

        synchronized (this)
        {
            final List<OAuthClient> clientList;
            clientList = new ArrayList<>(this.clients.values());

            final long currentTime = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
            OAuthClient previousClient = null;

            clientList.sort(OAuthClient::compareTo);
            for (OAuthClient client : clientList)
            {
                boolean isObsolete = client.isObsolete(currentTime);

                if (previousClient != null &&
                        client.getUserIdentifier() != null &&
                        previousClient.getUserIdentifier().equals(client.getUserIdentifier()))
                    removeClient(previousClient.getInternalToken());
                if (isObsolete)
                    removeClient(client.getInternalToken());

                previousClient = isObsolete ? null : client;
            }
        }
    }
    //endregion


    //region Getter
    public OAuthCookieManager getCookieManager()
    {
        isProviderConfigured();
        return cookieManager;
    }

    public String getRedirectionUri()
    {
        isProviderConfigured();
        return redirectUri;
    }
    //endregions


    //region OAuthPacket
    public static class OAuthPacket
    {
        private String remoteAddr;
        private String internalToken;
        private OAuthCookieManager cookieManager;

        private URI redirectUri;
        private Map<String, String> requestHeaders;
        private String requestBody;


        OAuthPacket(String remoteAddr, URI redirectUri, String internalToken, OAuthCookieManager cookieManager)
        {
            this.remoteAddr = remoteAddr;
            this.redirectUri = redirectUri;
            this.internalToken = internalToken == null ? "" : internalToken;
            this.cookieManager = cookieManager;
        }


        void setHeaders(Map<String, String> headers)
        {
            this.requestHeaders = headers;
        }

        void setBody(String body)
        {
            this.requestBody = body;
        }

        public String getRemoteAddr()
        {
            return remoteAddr;
        }

        public URI getRedirectUri()
        {
            return redirectUri;
        }


        public HttpServletResponse toResponse(HttpServletResponse response)
                throws IOException
        {
            this.cookieManager.insertInternalToken(response, this.internalToken);
            response.sendRedirect(this.redirectUri.toString());
            return response;
        }

        public Response.ResponseBuilder toResponse(Response.ResponseBuilder response)
        {
            if (response == null)
                response = Response.temporaryRedirect(this.redirectUri);
            else
                response.status(Response.Status.TEMPORARY_REDIRECT).location(this.redirectUri);

            return this.cookieManager.insertInternalToken(response, this.internalToken);
        }
    }

    public static OAuthPacket packetFrom(HttpServletRequest httpRequest, OAuthCookieManager cookieManager)
            throws URISyntaxException
    {
        URI originUri = new URI(httpRequest.getRequestURI());
        String internalKey = cookieManager.extractInternalToken(httpRequest);
        String remoteAddr = retrieveRemoteAddress(httpRequest);

        return new OAuthPacket(remoteAddr, originUri, internalKey, cookieManager);
    }
    //endregion

    //region OAuthProviderResponse
    public static class OAuthProviderResponse
    {
        final OAuthClient client;
        final URI redirectUri;
        final Map<String, String> headers;
        final String body;

        public OAuthProviderResponse(OAuthClient client, URI redirectUri, Map<String, String> headers, String body)
        {
            this.client = client;
            this.redirectUri = redirectUri;
            this.headers = headers;
            this.body = body;
        }

        public OAuthClient getClient()
        {
            return client;
        }

        public URI getRedirectUri()
        {
            return redirectUri;
        }

        public Map<String, String> getHeaders()
        {
            return headers;
        }

        public String getBody()
        {
            return body;
        }
    }
    //endregion
}