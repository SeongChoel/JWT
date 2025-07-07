package com.example.jwt.global.security;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.Rq;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final Rq rq;
    private final MemberService memberService;
    private boolean isAuthorizationHeader(HttpServletRequest request) {

        String authorizationHeader = request.getHeader("Authorization");

        if(authorizationHeader == null) {
            return false;
        }

        if(!authorizationHeader.startsWith("Bearer ")) {
            return false;
        }

        return true;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(isAuthorizationHeader(request)) {
            String authorizationHeader = request.getHeader("Authorization");
            String authToken = authorizationHeader.substring("Bearer ".length());

            String[] tokenBits =authToken.split(" ",2);
            if(tokenBits.length<2) {
                filterChain.doFilter(request, response); // 시큐리티가 처리함
                return;
            }

            String apikey = tokenBits[0];
            String accessToken = tokenBits[1];

            //여기서 터짐 왜냐하면 만료된 인증키니까
            Optional<Member> opAccMember = memberService.getMemberByAccessToken(accessToken);

            if(opAccMember.isEmpty()) {

                //재발급 로직
                Optional<Member> opApiMember = memberService.findByApiKey(apikey);

                //만약 API 비어있으면 , 막 재발급을 해주면 안된다
                if(opApiMember.isEmpty()) {
                    filterChain.doFilter(request, response); // 시큐리티가 처리함
                    return;
                }

                //API 키로 회원을 찾았으니, 재발급
                String newAccessToken =memberService.genAccessToken(opApiMember.get());
                response.addHeader("Authorization", "Bearer " + newAccessToken);

                //로그인 정보 설정
                Member actor = opApiMember.get();
                rq.setLogin(actor);

                filterChain.doFilter(request, response); // 시큐리티가 처리함
                return;
            }

            Member actor = opAccMember.get();
            rq.setLogin(actor);

            filterChain.doFilter(request, response);
        }
        else {
            Cookie[] cookies = request.getCookies();
            if(cookies==null) {
                filterChain.doFilter(request, response);
                return;
            }

            for(Cookie cookie : cookies) {
                if(cookie.getName().equals("accessToken")) {
                    String accessToken = cookie.getValue();

                    Optional<Member> opMember = memberService.getMemberByAccessToken(accessToken);
                    if(opMember.isEmpty()) {
                        filterChain.doFilter(request, response);
                        return;
                    }
                    Member actor = opMember.get();
                    rq.setLogin(actor);
                }
            }
        }

        filterChain.doFilter(request, response);
    }
}
