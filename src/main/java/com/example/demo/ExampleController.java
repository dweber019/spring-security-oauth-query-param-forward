package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleController {

  @Autowired
  private OAuth2AuthorizedClientService authorizedClientService;

  @GetMapping(value="/debug")
  public ResponseEntity<String> get(Model model, OAuth2AuthenticationToken authentication) {
    OAuth2AuthorizedClient client = authorizedClientService
        .loadAuthorizedClient(
            authentication.getAuthorizedClientRegistrationId(),
            authentication.getName());
    
    return new ResponseEntity<>("User: " + client.getPrincipalName(), HttpStatus.OK);
  }

}
