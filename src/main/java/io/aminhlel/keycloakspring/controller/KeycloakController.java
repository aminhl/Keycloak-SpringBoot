package io.aminhlel.keycloakspring.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/auth")
public class KeycloakController {

    @GetMapping
    @PreAuthorize("hasRole('client_user')")
    public String forPublic(){
        return "Hello from Springboot & Keycloak";
    }

    @GetMapping(value = "/admin")
    @PreAuthorize("hasRole('client_admin')")
    public String forAdmin(){
        return "Hello from Springboot & Keycloak - Admin";
    }

}
