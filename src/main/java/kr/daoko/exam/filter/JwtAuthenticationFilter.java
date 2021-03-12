package kr.daoko.exam.filter;

import kr.daoko.exam.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request); // token resolve
        if(token != null && jwtTokenProvider.validateToken(token)) { // token이 valid 할 경우
            Authentication authentication = jwtTokenProvider.getAuthentication(token); // jwtTokenProvider를 통해 인증 정보를 가져옴.
            SecurityContextHolder.getContext().setAuthentication(authentication); // 가져온 인증 정보를 설정함.
        }
        chain.doFilter(request, response);
    }
}
