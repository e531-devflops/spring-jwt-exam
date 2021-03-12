package kr.daoko.exam.config;

import kr.daoko.exam.filter.JwtAuthenticationFilter;
import kr.daoko.exam.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/console/**"); // 해당 경로의 필터링 제외
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable() // REST API 이므로 disable. 기본 설정은 비 인증시 로그인 화면으로 redirect 됨.
                .csrf().disable() // REST API 이므로 disable.
                .authorizeRequests() // 다음 request에 대한 사용 권한 확인
                .antMatchers("/admin/**").hasRole("ADMIN") // ADMIN 권한 만 접근 가능
                .antMatchers("/user/**").hasRole("USER") // USER 권한 만 접근 가능
                .antMatchers("/**").permitAll().and() // 누구나 접근 가능
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class); // ID/PW 인증 필터 전에 jwt token 삽입
    }
}
