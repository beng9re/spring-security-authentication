package nextstep.security.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nextstep.security.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.io.IOException;

public class BasicAuthenticationFilter implements Filter {
    private static final String BASIC_TYPE = "Basic";
    private final AuthenticationManager authenticationManager;

    public BasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        final String authorization = ((HttpServletRequest) request).getHeader(HttpHeaders.AUTHORIZATION);
        if (isNotBasic(authorization)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            BasicToken basicAuthentication = BasicToken.parse((HttpServletRequest) request);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken.from(basicAuthentication);

            Authentication authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

            SecurityContextHolder.getContext().setAuthentication(authenticate);

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
            ((HttpServletResponse) response).setStatus(HttpStatus.UNAUTHORIZED.value());
        }
    }



    private boolean isNotBasic(String authorization) {
        return authorization == null || !BASIC_TYPE.equals(authorization.split(" ")[0]);
    }
}
