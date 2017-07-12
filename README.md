KairosDB - OAuth2 module
========================
This module, used with the [authentication manager](https://github.com/Kratos-ISE/kairosdb-auth-manager), allow users to be authenticated with OAuth2 protocol.

How to use OAuth2
-----------------
To use this module, some interface must be implemented :

### OAuthProvider
Firstly, to communicate with a provider, an ``OAuthProvider`` class must be created.  
It give information and methods for the module to provide authentication.

````java
public interface OAuthProvider
{
    /**
     * Setup the client identifier (applicationToken and secretToken)
     * to bind your application with the provider
     */
    OAuthProvider setup(String clientId, String clientSecret);

    /**
     * Setup the URI where the provider redirect yours application
     * users after authentication
     */
    OAuthProvider setup(String redirectUri);

    /**
     * If the provider need more information (like scope for Google),
     * you can get it here.
     * <p><i>(See the provider documentation for more information)</i></p>
     */
    OAuthProvider setup(Properties properties) throws OAuthConfigurationException;

    /**
     * Configure the OAuthProvider with settings
     */
    void configure() throws OAuthConfigurationException;

    /**
     * Check if the provider is already configured
     */
    boolean isConfigured();

    /**
     * Start authentication flow with OAuth2.
     */
    OAuthService.OAuthProviderResponse startAuthentication(URI originUri) throws OAuthFlowException;

    /**
     * Finish authentication flow with OAuth2.
     */
    OAuthService.OAuthProviderResponse finishAuthentication(OAuthenticatingClient oAuthenticatingClient,
                                                            String code, String state,
                                                            Function<String, String> internalTokenGenerator)
            throws OAuthFlowException;
}
````
 > See the [Google provider implementation](src/main/java/org/kairosdb/security/oauth2/provider/google/OAuthGoogleProvider.java) if example is needed

### OAuthCookieManager
To avoid private token sharing, a mecanism was created to generate internal token, which can be shared with the client into a cookie.  
For security reason, you can implement your ``OAuthCookieManager`` which can obfuscate this internal token.

````java
public interface OAuthCookieManager
{
    /**
     * Insert a cookie with the internal token into the response
     */
    HttpServletResponse insertInternalToken(HttpServletResponse response, String internalToken);

    /**
     * Insert a cookie with the internal token into the response
     */
    Response.ResponseBuilder insertInternalToken(Response.ResponseBuilder response, String internalToken);

    /**
     * Extract the internal token from the request
     */
    String extractInternalToken(HttpServletRequest request);
}
````
> See the [simple cookie manager implementation](src/main/java/org/kairosdb/security/oauth2/cookie/SimpleCookieManager.java) if example is needed

### OAuthPlugin
Finally, to add modularity and filter with precision to KairosDB, you can create ``OAuthPlugin``.  
``OAuthPlugin``, thanks to the provider, can known unique identifiers and create a restriction for each user.

````java
public interface OAuthPlugin
{
    /**
     * Configure OAuth plugin with Properties
     */
    void configure(Properties properties);

    /**
     * Check if the user is allowed to access to resources.
     */
    boolean isAllowed(OAuthenticatedClient client, ServletRequest httpRequest) throws UnauthorizedClientResponse;
}
````

How to configure
----------------
This module can be easily configured throw the property file, read by KairosDB.

### Module configuration _(required)_
* `kairosdb.service.oauth=org.kairosdb.security.oauth2.core.OAuthModule` : Enable the OAuth2 KairosDB service
* `kairosdb.security.oauth2.provider` : Classpath of the provider implementation
* `kairosdb.security.oauth2.cookie.manager` : Classpath of the cookie manager implementation
* `kairosdb.security.oauth2.priority_weight` : Priority weight to choose which authentication use

### Provider configuration _(can changed, depends of the provider used)_
_Required for the module, for any provider_
* ``kairosdb.security.oauth2.clientId`` : Client ID, provided by the provider
* ``kairosdb.security.oauth2.clientSecret`` : Client Secret, provided by the provider
* ``kairosdb.security.oauth2.redirectionUri`` : Redirection URI, used bu the provider to get the client information

_For Google implementation_
* ``kairosdb.security.oauth2.google.scope`` : Google OAuth2 scope

### Path configuration _(required)_
* ``kairosdb.security.oauth2.filters.path.AAA=XXX`` : Enable OAuth authentication on XXX
* ``kairosdb.security.oauth2.filters.path.api=/api/*|Post`` : Enable OAuth authentication on `/api/*` for `POST` method. For more information, see [authentication manager for KairosDB](https://github.com/Kratos-ISE/kairosdb-auth-manager#path-configuration-for-utilspathtofilter).

License
-------
This module is licensed under the MIT license. See [License file](LICENSE) for more information.
