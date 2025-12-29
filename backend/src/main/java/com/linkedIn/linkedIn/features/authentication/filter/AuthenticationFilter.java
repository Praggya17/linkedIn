package com.linkedIn.linkedIn.features.authentication.filter;

import com.linkedIn.linkedIn.features.authentication.model.AuthenticationUser;
import com.linkedIn.linkedIn.features.authentication.services.AuthenticationService;
import com.linkedIn.linkedIn.features.authentication.utils.JsonWebToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class AuthenticationFilter extends HttpFilter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationFilter.class);

    private final List<String> unsecuredEndpoints = Arrays.asList(
            "/api/v1/authentication/register",
            "/api/v1/authentication/login",
            "/api/v1/authentication/send-password-reset-token",
            "/api/v1/authentication/reset-password"
    );

    private final JsonWebToken jsonWebToken;
    private final AuthenticationService authenticationService;

    public AuthenticationFilter(JsonWebToken jsonWebToken, AuthenticationService authenticationService) {
        this.jsonWebToken = jsonWebToken;
        this.authenticationService = authenticationService;
    }

    @Override
    public void doFilter(HttpServletRequest request, HttpServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
       logger.info("Incoming Request: Method={}, Path={}", request.getMethod(), request.getRequestURI());
       logger.info("Request Headers - Authorization: {}", request.getHeader("Authorization"));

       response.addHeader("Access-Control-Allow-Origin" , "*");
       response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
       response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

       if("OPTIONS".equalsIgnoreCase(request.getMethod())) {
           logger.info("Handling preflight OPTIONS request for path: {}", request.getRequestURI());
           response.setStatus(HttpServletResponse.SC_OK);
           return;
       }

         String path = request.getRequestURI();
            if (unsecuredEndpoints.contains(path)) {
                logger.info("Unsecured endpoint accessed: {}", path);
                chain.doFilter(request, response);
                return;
            }

            try{
                logger.info("Checking authorization for secured endpoint: {}", path);
                String AuthorisationHeader = request.getHeader("Authorization");
                String token = AuthorisationHeader.substring(7);

                if(jsonWebToken.isTokenExpired(token)){
                    logger.warn("Token expired for path: {}", path);
                    throw new ServletException("Token is invalid or expired");
                }
                String email = jsonWebToken.extractEmail(token);
                logger.info("Token validated for user: {}", email);
                AuthenticationUser user = authenticationService.getUser(email);
                request.setAttribute("authenticatedUser", user);
                logger.info("User attribute set in request for: {}", email);

                chain.doFilter(request, response);

            } catch (Exception e) {
                logger.error("Authorization error: {}", e.getMessage(), e);
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"message\": \"Unauthorized: Valid token is missing " + "\"}");

            }
    }
}
