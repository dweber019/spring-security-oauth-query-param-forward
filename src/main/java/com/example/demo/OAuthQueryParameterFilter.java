package com.example.demo;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.SCOPE;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import org.apache.catalina.connector.RequestFacade;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Order(-101) // Security is -100
@Component
public class OAuthQueryParameterFilter implements Filter {

  public static final String OAUTH_QUERY_PARAMETER_SESSION_NAME = "oAuthQueryParams";
  public static final String OAUTH_PARAMETER_PROMPT = "prompt";
  public static final String OAUTH_PARAMETER_LOGIN_HINT = "login_hint";
  public static final String OAUTH_PARAMETER_KC_IDP_HINT = "kc_idp_hint";
  private static final Set<String> VALID_QUERY_PARAMETERS = Set.of(SCOPE, OAUTH_PARAMETER_PROMPT, OAUTH_PARAMETER_LOGIN_HINT, OAUTH_PARAMETER_KC_IDP_HINT);

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    RequestFacade requestFacade = null;
    if (request instanceof RequestFacade) {
      requestFacade = ((RequestFacade) request);
    }

    if (requestFacade != null && requestFacade.getQueryString() != null && !requestFacade.getQueryString().equals("")) {
      requestFacade.getSession().setAttribute(OAUTH_QUERY_PARAMETER_SESSION_NAME, parseQuery(requestFacade));
    }

    chain.doFilter(request, response);
  }

  private static Map<String, String[]> parseQuery(RequestFacade requestFacade) {
    return requestFacade.getParameterMap().entrySet().stream()
      .filter(stringEntry -> VALID_QUERY_PARAMETERS.contains(stringEntry.getKey()))
      .collect(Collectors.toMap(Entry::getKey, Entry::getValue));
  }
}
