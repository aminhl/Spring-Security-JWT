package com.aminhl.security.auth;

import lombok.Builder;

@Builder
public record AuthenticationResponse(String accessToken) {
}
