package com.securityTemplate.demojwt.Jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final String SECRET_KEY = "586E3272357538782F413F4428472B4B6250655368566B597033733676397924";

    /**
     * The function `getToken` returns a token for a given `UserDetails` object
     * using an empty
     * `HashMap`.
     * 
     * @param user The `user` parameter is an object of type `UserDetails` which
     *             likely contains
     *             information about a user, such as their username, password, and
     *             other relevant details.
     * @return The `getToken` method is being called with an empty `HashMap` and the
     *         `UserDetails`
     *         object as parameters, and the result of this method call is being
     *         returned.
     */
    public String getToken(UserDetails user) {
        return getToken(new HashMap<>(), user);
    }

    /**
     * The function generates a JWT token with specified extra claims and user
     * details.
     * 
     * @param extraClaims Extra claims to be included in the JWT token, such as
     *                    custom user information
     *                    or additional metadata.
     * @param user        The `user` parameter in the `getToken` method is of type
     *                    `UserDetails` and
     *                    represents the details of the user for whom the token is
     *                    being generated. It is used to set the
     *                    subject of the JWT token to the username of the user.
     * @return A JWT (JSON Web Token) is being returned by the `getToken` method.
     */
    private String getToken(Map<String, Object> extraClaims, UserDetails user) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * The function `getKey` decodes a base64-encoded secret key and returns an HMAC
     * key.
     * 
     * @return A Key object is being returned.
     */
    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * The function `getUsernameFromToken` returns the subject claim from a given
     * token.
     * 
     * @param token A token is a piece of data that is used to authenticate a user
     *              or provide access to
     *              a system or service. It is often a string of characters that is
     *              generated by the system and
     *              passed along with requests to verify the identity of the user.
     * @return The method `getUsernameFromToken` is returning the subject claim from
     *         the token.
     */
    public String getUsernameFromToken(String token) {
        return getClaim(token, Claims::getSubject);
    }

    /**
     * The function `isTokenValid` checks if a token is valid by comparing the
     * username extracted from
     * the token with the username in the user details and verifying if the token is
     * not expired.
     * 
     * @param token       A token is a string that represents the authentication
     *                    credentials of a user. It is
     *                    typically generated by a server and provided to a client
     *                    for authentication purposes.
     * @param userDetails UserDetails is an object that contains details about a
     *                    user, such as their
     *                    username, password, and other relevant information. In the
     *                    context of the method isTokenValid,
     *                    userDetails is used to compare the username extracted from
     *                    the token with the username stored in
     *                    the UserDetails object to validate the token.
     * @return The method is returning a boolean value, which indicates whether the
     *         token is valid for
     *         the given user details.
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * The function `getAllClaims` parses a JWT token to extract and return its
     * claims.
     * 
     * @param token The `token` parameter in the `getAllClaims` method is a string
     *              that represents a
     *              JSON Web Token (JWT). This token is used for authentication and
     *              contains encoded information
     *              about the user or client making the request. The method parses
     *              the JWT token to extract the
     *              claims (payload data) embedded within it
     * @return The method `getAllClaims` is returning a `Claims` object.
     */
    private Claims getAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * The function `getClaim` retrieves all claims from a token and applies a
     * function to resolve a
     * specific claim.
     * 
     * @param token          A token is a piece of information that is used to
     *                       authenticate a user or provide
     *                       access to a system or resource. It is typically a
     *                       string of characters that is passed along with
     *                       a request to verify the identity of the user.
     * @param claimsResolver The `claimsResolver` parameter is a `Function` that
     *                       takes a `Claims`
     *                       object as input and returns a result of type `T`. It is
     *                       used to extract specific information or
     *                       data from the `Claims` object obtained from the token.
     * @return The `getClaim` method returns the result of applying the
     *         `claimsResolver` function to
     *         the `Claims` object obtained from `getAllClaims(token)`.
     */
    public <T> T getClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * The function `getExpiration` returns the expiration date of a token by
     * extracting the expiration
     * claim using a helper method.
     * 
     * @param token A token is a string that represents a user's authentication
     *              credentials or access
     *              rights. It is typically used for security purposes to verify the
     *              identity of a user and grant
     *              access to certain resources or services.
     * @return The method `getExpiration` is returning the expiration date of the
     *         token extracted from
     *         the claim using the `Claims::getExpiration` method.
     */
    private Date getExpiration(String token) {
        return getClaim(token, Claims::getExpiration);
    }

    /**
     * The function `isTokenExpired` checks if a token has expired by comparing its
     * expiration date with
     * the current date.
     * 
     * @param token The `token` parameter is a string that represents a token used
     *              for authentication or
     *              authorization purposes in a system.
     * @return The method isTokenExpired is returning a boolean value, which
     *         indicates whether the token
     *         has expired or not.
     */
    private boolean isTokenExpired(String token) {
        return getExpiration(token).before(new Date());
    }

}
