package kr.daoko.exam.controller;

import kr.daoko.exam.model.User;
import kr.daoko.exam.provider.JwtTokenProvider;
import kr.daoko.exam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class UserController {
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    @PostMapping("/join")
    public Long join(@RequestBody Map<String, String> user) {
        return userRepository.save(User.builder()
                .email(user.get("email"))
                .password(passwordEncoder.encode(user.get("password")))
                .roles(Collections.singletonList("ROLE_USER"))
                .build()).getId();
    }

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> user) {
        User member = userRepository.findByEmail(user.get("email")).orElseThrow(() -> new IllegalArgumentException("not registered email."));
        if(!passwordEncoder.matches(user.get("password"), member.getPassword())) {
            throw new IllegalArgumentException("wrong password");
        }

        return jwtTokenProvider.createToken(member.getUsername(), member.getRoles());
    }

    @GetMapping("/user/auth")
    public String userAuth() {
        return "authorize success";
    }

    @GetMapping("/admin/auth")
    public String adminAuth() {
        return "authorize success";
    }
}
