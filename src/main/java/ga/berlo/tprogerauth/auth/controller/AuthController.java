package ga.berlo.tprogerauth.auth.controller;

import ga.berlo.tprogerauth.auth.exception.LoginException;
import ga.berlo.tprogerauth.auth.exception.RegistrationException;
import ga.berlo.tprogerauth.auth.model.ErrorResponse;
import ga.berlo.tprogerauth.auth.model.TokenResponse;
import ga.berlo.tprogerauth.auth.model.User;
import ga.berlo.tprogerauth.auth.service.ClientService;
import ga.berlo.tprogerauth.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final ClientService clientService;
    private final TokenService tokenService;

    @PostMapping
    public ResponseEntity<String> register(@RequestBody User user) {
        clientService.register(user.getClientId(), user.getClientSecret());
        return ResponseEntity.ok("Registered");
    }

    @PostMapping("/token")
    public TokenResponse getToken(@RequestBody User user) {
        clientService.checkCredentials(user.getClientId(), user.getClientSecret());
        return new TokenResponse(tokenService.generateToken(user.getClientId()));
    }

    @ExceptionHandler({RegistrationException.class, LoginException.class})
    public ResponseEntity<ErrorResponse> handleUserRegistrationException(RuntimeException ex){
        return ResponseEntity
                .badRequest()
                .body(new ErrorResponse(ex.getMessage()));
    }
}
