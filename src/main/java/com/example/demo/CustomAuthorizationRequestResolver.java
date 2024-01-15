package com.example.demo;

import static com.example.demo.OAuthQueryParameterFilter.OAUTH_PARAMETER_KC_IDP_HINT;
import static com.example.demo.OAuthQueryParameterFilter.OAUTH_PARAMETER_LOGIN_HINT;
import static com.example.demo.OAuthQueryParameterFilter.OAUTH_PARAMETER_PROMPT;
import static com.example.demo.OAuthQueryParameterFilter.OAUTH_QUERY_PARAMETER_SESSION_NAME;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.WebRequest;

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
  private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;

  public CustomAuthorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository) {

    this.defaultAuthorizationRequestResolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository, "/oauth2/authorization");
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    OAuth2AuthorizationRequest authorizationRequest =
        this.defaultAuthorizationRequestResolver.resolve(request);

    return authorizationRequest != null ?
    customAuthorizationRequest(authorizationRequest) :
    null;
  }

  @Override
  public OAuth2AuthorizationRequest resolve(
      HttpServletRequest request, String clientRegistrationId) {

    OAuth2AuthorizationRequest authorizationRequest =
        this.defaultAuthorizationRequestResolver.resolve(
            request, clientRegistrationId);

    return authorizationRequest != null ?
    customAuthorizationRequest(authorizationRequest) :
    null;
  }

  private OAuth2AuthorizationRequest customAuthorizationRequest(
      OAuth2AuthorizationRequest authorizationRequest) {
    Builder oAuth2AuthorizationRequestBuilder = OAuth2AuthorizationRequest.from(authorizationRequest);
    Map<String, Object> additionalParameters =
        new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
    LinkedHashSet<String> additionalScopes = new LinkedHashSet<>(authorizationRequest.getScopes());

    Object sessionParams = RequestContextHolder.currentRequestAttributes().getAttribute(OAUTH_QUERY_PARAMETER_SESSION_NAME, WebRequest.SCOPE_SESSION);
    if (sessionParams instanceof Map) {
      Map<String, String[]> authParams = (Map<String, String[]>) sessionParams;
      if (authParams.get(OAUTH_PARAMETER_PROMPT) != null && authParams.get(OAUTH_PARAMETER_PROMPT).length > 0) {
        additionalParameters.put(OAUTH_PARAMETER_PROMPT, authParams.get(OAUTH_PARAMETER_PROMPT)[0]);
      }
      if (authParams.get(OAUTH_PARAMETER_LOGIN_HINT) != null && authParams.get(OAUTH_PARAMETER_LOGIN_HINT).length > 0) {
        additionalParameters.put(OAUTH_PARAMETER_LOGIN_HINT, authParams.get(OAUTH_PARAMETER_LOGIN_HINT)[0]);
      }
      if (authParams.get(OAUTH_PARAMETER_KC_IDP_HINT) != null && authParams.get(OAUTH_PARAMETER_KC_IDP_HINT).length > 0) {
        additionalParameters.put(OAUTH_PARAMETER_KC_IDP_HINT, authParams.get(OAUTH_PARAMETER_KC_IDP_HINT)[0]);
      }
      if (authParams.get(SCOPE) != null && authParams.get(SCOPE).length > 0) {
        additionalScopes.addAll(Arrays.asList(authParams.get(SCOPE)));
      }
    }

    RequestContextHolder.currentRequestAttributes().setAttribute(OAUTH_QUERY_PARAMETER_SESSION_NAME, null, WebRequest.SCOPE_SESSION);

    return oAuth2AuthorizationRequestBuilder
        .additionalParameters(additionalParameters)
        .scopes(additionalScopes)
        .build();
  }
}
