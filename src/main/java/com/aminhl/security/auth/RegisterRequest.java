package com.aminhl.security.auth;

import lombok.Builder;

@Builder
public record RegisterRequest(String firstname, String lastname, String email, String password) {
}
