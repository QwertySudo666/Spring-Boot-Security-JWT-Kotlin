package aviatickets_api.security.jwt

import aviatickets_api.security.services.UserDetailsImpl
import io.jsonwebtoken.*
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.ResponseCookie
import org.springframework.stereotype.Component
import org.springframework.web.util.WebUtils
import java.util.*
import javax.servlet.http.HttpServletRequest

@Component
class JwtUtils {
    @Value("\${bezkoder.app.jwtSecret}")
    private val jwtSecret: String? = null

    @Value("\${bezkoder.app.jwtExpirationMs}")
    private val jwtExpirationMs = 0

    @Value("\${bezkoder.app.jwtCookieName}")
    private val jwtCookie: String? = null
    fun getJwtFromCookies(request: HttpServletRequest?): String? {
        val cookie = WebUtils.getCookie(request!!, jwtCookie!!)
        return cookie?.value
    }

    fun generateJwtCookie(userPrincipal: UserDetailsImpl): ResponseCookie {
        val jwt = generateTokenFromUsername(userPrincipal.username)
        return ResponseCookie.from(jwtCookie!!, jwt).path("/api").maxAge((24 * 60 * 60).toLong()).httpOnly(true)
            .build()
    }

    val cleanJwtCookie: ResponseCookie
        get() = ResponseCookie.from(jwtCookie!!, null.toString()).path("/api").build()

    fun getUserNameFromJwtToken(token: String?): String {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).body.subject
    }

    fun validateJwtToken(authToken: String?): Boolean {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken)
            return true
        } catch (e: SignatureException) {
            logger.error("Invalid JWT signature: {}", e.message)
        } catch (e: MalformedJwtException) {
            logger.error("Invalid JWT token: {}", e.message)
        } catch (e: ExpiredJwtException) {
            logger.error("JWT token is expired: {}", e.message)
        } catch (e: UnsupportedJwtException) {
            logger.error("JWT token is unsupported: {}", e.message)
        } catch (e: IllegalArgumentException) {
            logger.error("JWT claims string is empty: {}", e.message)
        }
        return false
    }

    fun generateTokenFromUsername(username: String?): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(Date().time + jwtExpirationMs))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact()
    }

    companion object {
        private val logger = LoggerFactory.getLogger(JwtUtils::class.java)
    }
}