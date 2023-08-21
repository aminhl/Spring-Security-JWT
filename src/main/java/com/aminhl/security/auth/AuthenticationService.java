package com.aminhl.security.auth;

import com.aminhl.security.config.JwtService;
import com.aminhl.security.token.Token;
import com.aminhl.security.token.TokenRepository;
import com.aminhl.security.token.TokenType;
import com.aminhl.security.user.Role;
import com.aminhl.security.user.User;
import com.aminhl.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken).build();
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
        revokeAllUserValidTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder().
                accessToken(jwtToken).build();
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
}
