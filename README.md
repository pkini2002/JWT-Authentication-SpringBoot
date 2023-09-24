# JWT-Authentication using SpringBoot 3.1.4

JWT stands for JSON Web Token. They are a popular way to implement authentication and authorization in web applications. 

A JWT is made up of three parts:
<br>
- `Header` : The header contains information about the token, such as the type of token (JWT) and the signing algorithm used.
- `Payload` : The payload is the main body of the token and contains the claims, which are statements about the user or other entity.
- `Signature` : The signature is used to verify the token's integrity. It is created by signing the header and payload with a secret or public/private key pair.

When a user logs in to a web application, the server generates a JWT and sends it back to the client. The client can then store the token in local storage or session storage.
When the user makes subsequent requests to the server, the client includes the JWT in the request header. The server can then verify the token and authenticate the user.

## Architecture of JWT Authentication Flow

<p align="center"><img src="https://github.com/pkini2002/NMAMIT-CSE-Labs-2020-24/assets/84091455/c39f242b-8d08-4a4d-92b5-74f76cdf6be0" width="500"></p>

## Steps to implement the project

- Navigate to <a href="https://start.spring.io/">Spring Initializr </a> and create a new Spring Boot Project

### Specifications

<table>
  <tr>
    <th>Type</th>
    <th>Value</th>
  </tr>
  <tr>
    <td>Language</td>
    <td>Java</td>
  </tr>
  <tr>
    <td>Build Automation tool</td>
    <td>Maven</td>
  </tr>
  <tr>
    <td>Spring Boot Version</td>
    <td>3.1.4</td>
  </tr>
  <tr>
    <td>Packaging</td>
    <td>JAR</td>
  </tr>
  <tr>
    <td>Java Version</td>
    <td>17</td>
  </tr>
</table>

### Dependencies Used

- Web Dependency

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

- Security

```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

- Lombok

```
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>
```

- JWT Dependencies

```
 <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-api -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>


     <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt-impl -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

### Steps

- Create an Endpoint to be secured by creating a controller package in order to create views

```
@RestController
public class HomeController {
    Logger logger = LoggerFactory.getLogger(HomeController.class);
    @RequestMapping("/test")
    public String test() {
        this.logger.warn("This is working message");
        return "Testing message";
    }
}
```

- Create In-Memory User with UserDetailService Bean

```
@Configuration
class MyConfig {
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.builder().
                username("DURGESH")
                .password(passwordEncoder().encode("DURGESH")).roles("ADMIN").
                build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
```

### Steps to implement JWT Token

- Make sure `spring-boot-starter-security` is there in pom.xml
- Create Class `JWTAthenticationEntryPoint` that implements `AuthenticationEntryPoint`. The method of this class is called whenever an exception is thrown due to an
- unauthenticated user trying to access the resource that required authentication.

```
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter writer = response.getWriter();
        writer.println("Access Denied !! " + authException.getMessage());
    }
}
```

- Create the `JWTHelper` class This class contains a method related to perform operations with jwt tokens like generateToken, validateToken, etc.

```
@Component
public class JwtHelper {

    //requirement :
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    //    public static final long JWT_TOKEN_VALIDITY =  60;
    private String secret = "afafasfafafasfasfasfafacasdasfasxASFACASDFACASDFASFASFDAFASFASDAADSCSDFADCVSGCFVADXCcadwavfsfarvf";

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //while creating the token -
    //1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.
    //3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
    //   compaction of the JWT to a URL-safe string
    private String doGenerateToken(Map<String, Object> claims, String subject) {

        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```
