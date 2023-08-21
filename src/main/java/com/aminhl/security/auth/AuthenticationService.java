package com.aminhl.security.auth;

import com.aminhl.security.config.JwtService;
import com.aminhl.security.token.Token;
import com.aminhl.security.token.TokenRepository;
import com.aminhl.security.token.TokenType;
import com.aminhl.security.user.Role;
import com.aminhl.security.user.User;
import com.aminhl.security.user.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;

import static com.aminhl.security.token.TokenType.BEARER;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .firstname(registerRequest.firstname())
                .lastname(registerRequest.lastname())
                .email(registerRequest.email())
                .password(passwordEncoder.encode(registerRequest.password()))
                .role(Role.ADMIN)
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
               new UsernamePasswordAuthenticationToken(
                       authenticationRequest.email(),
                       authenticationRequest.password()
               )
        );
        var user = userRepository.findByEmail(authenticationRequest.email())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserValidTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        final Token token = Token
                .builder()
                .token(jwtToken)
                .tokenType(BEARER)
                .user(user)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserValidTokens(User user){
        final List<Token> userValidTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (userValidTokens.isEmpty()) return;
        userValidTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(userValidTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return;
        final String refreshToken = authHeader.substring(7);
        final String userEmail = jwtService.extractUsername(refreshToken);
        final User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("username " + userEmail + " not found!"));
        if (jwtService.isTokenValid(refreshToken, user)){
            final String accessToken = jwtService.generateToken(user);
            revokeAllUserValidTokens(user);
            saveUserToken(user, accessToken);
            final AuthenticationResponse authResponse
                    = AuthenticationResponse.builder()
                                            .accessToken(accessToken)
                                            .refreshToken(refreshToken)
                                            .build();
            new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
        }
    }
}
