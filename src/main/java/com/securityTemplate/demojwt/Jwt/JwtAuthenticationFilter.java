package com.securityTemplate.demojwt.Jwt;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.util.StringUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

   /**
    * The doFilterInternal method checks for a token in the request, validates it, and sets the
    * authentication in the SecurityContextHolder if the token is valid.
    * 
    * @param request The `request` parameter in the `doFilterInternal` method represents an HTTP
    * servlet request. It contains information about the client's request to the server, such as the
    * request URL, headers, parameters, and body.
    * @param response The `response` parameter in the `doFilterInternal` method of a filter in Spring
    * Framework represents the HTTP response that will be sent back to the client. It allows you to
    * manipulate the response, set headers, write content, and control the flow of the response.
    * @param filterChain The `filterChain` parameter in the `doFilterInternal` method is used to invoke
    * the next filter in the chain. It allows the request to proceed through the chain of filters in
    * the servlet container. If you call `filterChain.doFilter(request, response)` within the method,
    * it will pass
    */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       
        final String token = getTokenFromRequest(request);
        final String username;

        if (token==null)
        {
            filterChain.doFilter(request, response);
            return;
        }

        username=jwtService.getUsernameFromToken(token);

        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            UserDetails userDetails=userDetailsService.loadUserByUsername(username);

            if (jwtService.isTokenValid(token, userDetails))
            {
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        
        filterChain.doFilter(request, response);
    }

   /**
    * The function `getTokenFromRequest` extracts a token from the Authorization header in an HTTP
    * request if it starts with "Bearer ".
    * 
    * @param request The `request` parameter is of type `HttpServletRequest`, which is an interface
    * that provides request information for HTTP servlets. It allows you to retrieve information about
    * the request made by the client, such as headers, parameters, and attributes.
    * @return The method `getTokenFromRequest` returns a String value, which is the token extracted
    * from the Authorization header of the HttpServletRequest. If the Authorization header starts with
    * "Bearer ", it extracts the token part (excluding "Bearer ") and returns it. Otherwise, it returns
    * null.
    */
    private String getTokenFromRequest(HttpServletRequest request) {
        final String authHeader=request.getHeader(HttpHeaders.AUTHORIZATION);

        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer "))
        {
            return authHeader.substring(7);
        }
        return null;
    }



    
}
