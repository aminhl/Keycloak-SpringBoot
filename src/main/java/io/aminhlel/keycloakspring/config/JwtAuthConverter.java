package io.aminhlel.keycloakspring.config;

import com.nimbusds.jwt.JWTClaimNames;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter;

    @Value("${jwt.auth.converter.resource-access}")
    private String resourceAccess;
    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;
    private final String ROLES = "roles";
    private final String DEFAULT_ROLE_PREFIX = "ROLE_";
    @Value("${jwt.auth.converter.principal-attribute}")
    private String principalAttribute;

    public JwtAuthConverter() {
        jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    }

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()
        ).collect(Collectors.toSet());
        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipalClaimName(jwt)
        );
    }

    private String getPrincipalClaimName(Jwt jwt) {
        String claimName = JWTClaimNames.SUBJECT;
        if (principalAttribute != null)
            claimName = principalAttribute;
        return jwt.getClaim(claimName);
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        if (jwt.getClaim(this.resourceAccess) == null)
            return Set.of();
        resourceAccess = jwt.getClaim(this.resourceAccess);
        if (jwt.getClaim(this.resourceAccess) == null)
            return Set.of();
        resource = (Map<String, Object>) resourceAccess.get(resourceId);
        resourceRoles = (Collection<String>) resource.get(ROLES);
        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority(DEFAULT_ROLE_PREFIX + role))
                .collect(Collectors.toSet());
    }
}
